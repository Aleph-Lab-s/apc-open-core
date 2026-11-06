from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Iterable
from zipfile import ZIP_DEFLATED, ZipFile

from .intake import CustomerIntake
from apc_product.version import PRODUCT, VERSION


BUNDLED_DISTS = (
    "pydantic",
    "pydantic-core",
    "cryptography",
    "cffi",
    "pycparser",
    "typing-extensions",
    "annotated-types",
    "typing-inspection",
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _wheel_hash(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def _copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, symlinks=True)


def _copy_distribution_files(dist: Any, site_root: Path, dst_root: Path, *, skip_pyc: bool = True) -> None:
    for file_entry in dist.files or ():
        rel = Path(str(file_entry))
        if rel.is_absolute() or ".." in rel.parts:
            raise RuntimeError(f"unsafe dependency path: {rel}")
        if skip_pyc and (rel.suffix == ".pyc" or "__pycache__" in rel.parts):
            continue
        src = site_root / rel
        if not src.exists() and not src.is_symlink():
            raise RuntimeError(f"dependency file missing from environment: {src}")
        dst = dst_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_symlink():
            if dst.exists() or dst.is_symlink():
                dst.unlink()
            dst.symlink_to(os.readlink(src))
        else:
            shutil.copy2(src, dst)


class DeliveryFactory:
    """Build one customer-facing APC runtime artifact from a validated intake.

    The customer never receives the development repository. Every profile is a
    single native primary artifact containing the APC runtime needed for that
    delivery model. Customer credentials, private keys and provider secrets are
    always external to the artifact.
    """

    def __init__(self, source_root: str | Path):
        self.root = Path(source_root).resolve()
        self._cache_root = Path(tempfile.mkdtemp(prefix="apc-delivery-cache-"))
        self._standard_wheel_cache: Path | None = None
        self._runtime_template_cache: Path | None = None
        self._oci_image_cache: Path | None = None

    def close(self) -> None:
        if self._cache_root.exists():
            shutil.rmtree(self._cache_root, ignore_errors=True)

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def build(self, intake: CustomerIntake, output_dir: str | Path) -> Path:
        intake.validate()
        out = Path(output_dir).resolve()
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        fmt = intake.resolved_artifact_format()
        if fmt == "wheel":
            artifact = self._build_bundled_wheel(out)
        elif fmt == "deb":
            artifact = self._build_deb(out)
        elif fmt == "run":
            artifact = self._build_run(out)
        elif fmt == "oci":
            artifact = self._build_oci_image(out)
        elif fmt in {"kubernetes-bundle", "openshift-bundle"}:
            artifact = self._build_kubernetes_bundle(out, openshift=(fmt == "openshift-bundle"))
        else:
            raise ValueError(fmt)
        return self._write_manifest(out, intake, artifact)

    # ---------- common APC runtime material ----------

    def _build_standard_wheel(self, out: Path) -> Path:
        """Build the normal PEP 427 APC wheel from this exact source tree."""
        if self._standard_wheel_cache and self._standard_wheel_cache.exists():
            return self._standard_wheel_cache
        build_out = self._cache_root / "standard-wheel"
        build_out.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(self.root / "build", ignore_errors=True)
        shutil.rmtree(self.root / "apc_y.egg-info", ignore_errors=True)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                str(self.root),
                "-w",
                str(build_out),
            ],
            cwd=self.root,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"wheel build failed: {result.stderr.strip() or result.stdout.strip()}")
        wheels = sorted(build_out.glob("*.whl"))
        if len(wheels) != 1:
            raise RuntimeError("expected exactly one APC source wheel")
        self._standard_wheel_cache = wheels[0]
        shutil.rmtree(self.root / "build", ignore_errors=True)
        shutil.rmtree(self.root / "apc_y.egg-info", ignore_errors=True)
        return self._standard_wheel_cache

    def _runtime_dependencies(self) -> list[Any]:
        from importlib import metadata

        missing: list[str] = []
        found: list[Any] = []
        for name in BUNDLED_DISTS:
            try:
                found.append(metadata.distribution(name))
            except metadata.PackageNotFoundError:
                missing.append(name)
        if missing:
            raise RuntimeError("customer-native build requires installed runtime dependencies: " + ", ".join(missing))
        return found

    def _build_bundled_wheel(self, out: Path) -> Path:
        """Create a target-specific single-file OEM wheel with runtime deps embedded.

        The regular source wheel is still the source of truth. We augment it with
        the exact tested dependency files and adjust the wheel metadata/tag to the
        current evaluation platform (CPython 3.13, Linux x86_64).
        """
        standard_dir = out / ".standard-wheel"
        standard_dir.mkdir(parents=True)
        standard = self._build_standard_wheel(standard_dir)
        with tempfile.TemporaryDirectory(prefix="apc-wheel-") as td:
            root = Path(td) / "wheel"
            root.mkdir()
            with ZipFile(standard) as zf:
                zf.extractall(root)

            import site
            site_root = Path(site.getsitepackages()[0]).resolve()
            for dist in self._runtime_dependencies():
                _copy_distribution_files(dist, site_root, root)
            # A wheel can only represent one distribution cleanly. Vendor the
            # dependency import trees/binaries but omit their separate dist-info
            # metadata; APC carries the exact versions in its delivery manifest
            # and consolidated third-party notice.
            for dep_info in root.glob("*.dist-info"):
                if dep_info.name != f"apc_y-{VERSION}.dist-info":
                    shutil.rmtree(dep_info)
            (root / "APC-THIRD-PARTY-NOTICES.txt").write_text(self._third_party_notices(), encoding="utf-8")

            dist_info = root / f"apc_y-{VERSION}.dist-info"
            metadata_path = dist_info / "METADATA"
            metadata_text = metadata_path.read_text(encoding="utf-8")
            lines = [
                line
                for line in metadata_text.splitlines()
                if not line.startswith("Requires-Dist: pydantic")
                and not line.startswith("Requires-Dist: cryptography")
            ]
            lines.append("Requires-Python: >=3.13") if not any(line.startswith("Requires-Python:") for line in lines) else None
            lines = [
                "Requires-Python: >=3.13" if line.startswith("Requires-Python:") else line
                for line in lines
            ]
            metadata_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            wheel_path = dist_info / "WHEEL"
            wheel_text = wheel_path.read_text(encoding="utf-8")
            wheel_text = "\n".join(
                "Root-Is-Purelib: false" if line.startswith("Root-Is-Purelib:") else line
                for line in wheel_text.splitlines()
            )
            wheel_text = "\n".join(
                "Tag: cp313-cp313-manylinux_2_17_x86_64" if line.startswith("Tag:") else line
                for line in wheel_text.splitlines()
            ) + "\n"
            wheel_path.write_text(wheel_text, encoding="utf-8")

            record_path = dist_info / "RECORD"
            records: list[str] = []
            for p in sorted(q for q in root.rglob("*") if q.is_file() and q != record_path):
                rel = p.relative_to(root).as_posix()
                data = p.read_bytes()
                records.append(f"{rel},sha256={_wheel_hash(data)},{len(data)}")
            records.append(f"{record_path.relative_to(root).as_posix()},,")
            record_path.write_text("\n".join(records) + "\n", encoding="utf-8")

            target = out / f"apc_y-{VERSION}-cp313-cp313-manylinux_2_17_x86_64.whl"
            if target.exists():
                target.unlink()
            with ZipFile(target, "w", compression=ZIP_DEFLATED) as zf:
                for p in sorted(q for q in root.rglob("*") if q.is_file()):
                    zf.write(p, p.relative_to(root).as_posix())
        shutil.rmtree(standard_dir, ignore_errors=True)
        return target

    def _build_runtime_tree(self, staging: Path) -> Path:
        """Create a compact private CPython + APC runtime for Linux artifacts.

        The runtime template is built once per DeliveryFactory so every native
        customer artifact is byte-for-byte derived from the same tested source
        and dependency set.
        """
        if self._runtime_template_cache and self._runtime_template_cache.exists():
            target = staging / "runtime"
            shutil.copytree(self._runtime_template_cache, target, symlinks=True)
            return target

        runtime = self._cache_root / "runtime-template"
        runtime.mkdir(parents=True, exist_ok=True)
        bin_dir = runtime / "bin"
        lib_root = runtime / "lib"
        site_root = lib_root / "python3.13" / "site-packages"
        stdlib_root = lib_root / "python3.13"
        bin_dir.mkdir(parents=True, exist_ok=True)
        site_root.mkdir(parents=True, exist_ok=True)

        python_bin = Path(sys.executable).resolve()
        if sys.version_info[:2] != (3, 13):
            raise RuntimeError(f"evaluation runtime must be CPython 3.13, found {sys.version.split()[0]}")
        shutil.copy2(python_bin, bin_dir / "python3.13")
        _copy_tree(Path(sysconfig_path("stdlib")), stdlib_root)

        wheel = self._build_standard_wheel(self._cache_root / "unused-wheel-output")
        with ZipFile(wheel) as zf:
            zf.extractall(site_root)
        import site
        env_site = Path(site.getsitepackages()[0]).resolve()
        for dist in self._runtime_dependencies():
            _copy_distribution_files(dist, env_site, site_root)

        ca = Path("/etc/ssl/certs/ca-certificates.crt")
        if ca.exists():
            cert_dst = runtime / "etc" / "ssl" / "certs" / "ca-certificates.crt"
            cert_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ca, cert_dst)

        libs_dir = runtime / "lib" / "x86_64-linux-gnu"
        libs_dir.mkdir(parents=True, exist_ok=True)
        binaries = [bin_dir / "python3.13"] + list(site_root.rglob("*.so"))
        dep_paths = self._collect_dynamic_dependencies(binaries)
        for source in sorted(dep_paths):
            target = libs_dir / source.name
            if target.exists():
                continue
            shutil.copy2(source, target)

        self._runtime_template_cache = runtime
        target = staging / "runtime"
        shutil.copytree(runtime, target, symlinks=True)
        return target

    def _collect_dynamic_dependencies(self, binaries: Iterable[Path]) -> set[Path]:
        results: set[Path] = set()
        seen: set[Path] = set()
        pending = [p.resolve() for p in binaries if p.exists()]
        while pending:
            binary = pending.pop()
            if binary in seen:
                continue
            seen.add(binary)
            proc = subprocess.run(["ldd", str(binary)], text=True, capture_output=True)
            if proc.returncode != 0:
                continue
            for line in proc.stdout.splitlines():
                line = line.strip()
                if "=>" in line:
                    _name, rhs = [part.strip() for part in line.split("=>", 1)]
                    path_token = rhs.split(" ", 1)[0]
                    if path_token.startswith("/"):
                        p = Path(path_token).resolve()
                        if p.exists():
                            results.add(p)
                            pending.append(p)
                elif line.startswith("/"):
                    p = Path(line.split(" ", 1)[0]).resolve()
                    if p.exists():
                        results.add(p)
                        pending.append(p)
        return results

    def _runtime_launcher(self, runtime_rel: str, command: str) -> str:
        return textwrap.dedent(
            f"""\
            #!/bin/sh
            set -eu
            APP_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
            export PYTHONHOME="$APP_ROOT/{runtime_rel}"
            export PYTHONPATH="$APP_ROOT/{runtime_rel}/lib/python3.13/site-packages${{PYTHONPATH:+:$PYTHONPATH}}"
            export LD_LIBRARY_PATH="$APP_ROOT/{runtime_rel}/lib/x86_64-linux-gnu${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}"
            exec "$APP_ROOT/{runtime_rel}/bin/python3.13" {command} "$@"
            """
        )

    def _build_deb(self, out: Path) -> Path:
        staging = out / ".deb-root"
        opt = staging / "opt" / "apc-enterprise"
        bin_dir = staging / "usr" / "bin"
        var_dir = staging / "var" / "lib" / "apc"
        opt.mkdir(parents=True)
        bin_dir.mkdir(parents=True)
        var_dir.mkdir(parents=True)
        self._build_runtime_tree(staging)
        # _build_runtime_tree writes /staging/runtime; move it into the final prefix.
        shutil.move(str(staging / "runtime"), str(opt / "runtime"))

        control = staging / "DEBIAN"
        control.mkdir(mode=0o755)
        control.chmod(0o755)
        (control / "control").write_text(
            "Package: apc-enterprise\n"
            f"Version: {VERSION}\n"
            "Section: security\n"
            "Priority: optional\n"
            "Architecture: amd64\n"
            "Maintainer: Aleph Labs\n"
            "Depends: libc6\n"
            "Description: APC action security continuity runtime\n",
            encoding="utf-8",
        )
        (control / "postinst").write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "if ! id apc >/dev/null 2>&1; then useradd --system --home /var/lib/apc --shell /usr/sbin/nologin apc; fi\n"
            "mkdir -p /var/lib/apc\n"
            "chown apc:apc /var/lib/apc\n"
            "exit 0\n",
            encoding="utf-8",
        )
        (control / "postinst").chmod(0o755)
        (control / "prerm").write_text("#!/bin/sh\nset -eu\nexit 0\n", encoding="utf-8")
        (control / "prerm").chmod(0o755)

        launcher = bin_dir / "apc-enterprise"
        launcher.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "APP_ROOT=/opt/apc-enterprise\n"
            "export PYTHONHOME=\"$APP_ROOT/runtime\"\n"
            "export PYTHONPATH=\"$APP_ROOT/runtime/lib/python3.13/site-packages${PYTHONPATH:+:$PYTHONPATH}\"\n"
            "export LD_LIBRARY_PATH=\"$APP_ROOT/runtime/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"\n"
            "export APC_DB_PATH=\"${APC_DB_PATH:-/var/lib/apc/apc-product.db}\"\n"
            "exec \"$APP_ROOT/runtime/bin/python3.13\" -m apc_product \"$@\"\n",
            encoding="utf-8",
        )
        launcher.chmod(0o755)

        # Default customer data location and version evidence.
        (opt / "INSTALLATION.json").write_text(
            json.dumps(
                {
                    "product": PRODUCT,
                    "version": VERSION,
                    "delivery": "linux-native",
                    "runtime": "private CPython 3.13",
                    "architecture": "amd64",
                    "credentials_included": False,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        deb = out / f"APC-Enterprise-{VERSION}-linux-amd64.deb"
        result = subprocess.run(["dpkg-deb", "--build", str(staging), str(deb)], text=True, capture_output=True)
        if result.returncode != 0:
            raise RuntimeError(f"dpkg-deb failed: {result.stderr.strip() or result.stdout.strip()}")
        shutil.rmtree(staging)
        return deb

    def _build_run(self, out: Path) -> Path:
        """Build a single-file, network-independent Linux installer."""
        staging = out / ".run-staging"
        staging.mkdir(parents=True)
        runtime = self._build_runtime_tree(staging)
        payload_dir = staging / "payload"
        payload_dir.mkdir()
        shutil.move(str(runtime), str(payload_dir / "runtime"))
        (payload_dir / "THIRD_PARTY_NOTICES.txt").write_text(self._third_party_notices(), encoding="utf-8")
        (payload_dir / "INSTALLATION.json").write_text(
            json.dumps(
                {
                    "product": PRODUCT,
                    "version": VERSION,
                    "delivery": "air-gapped-linux",
                    "runtime": "private CPython 3.13",
                    "architecture": "amd64",
                    "network_access_for_install": "not_required",
                    "credentials_included": False,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        payload_path = staging / "payload.tgz"
        with tarfile.open(payload_path, mode="w:gz", compresslevel=6) as tf:
            tf.add(payload_dir, arcname="payload")
        expected_sha = sha256(payload_path)

        run = out / f"APC-Enterprise-{VERSION}-airgapped-amd64.run"
        header = f"""#!/bin/sh
set -eu
PREFIX=${{APC_INSTALL_PREFIX:-/opt/apc-enterprise}}
SELF="$0"
PAYLOAD_LINE="$(grep -n '^__APC_PAYLOAD_START__$' "$SELF" | tail -n 1 | cut -d: -f1)"
[ -n "$PAYLOAD_LINE" ] || {{ echo 'APC payload marker missing' >&2; exit 1; }}
PAYLOAD="$PREFIX/.apc-payload.tgz"
mkdir -p "$PREFIX"
tail -n +$((PAYLOAD_LINE + 1)) "$SELF" | base64 -d > "$PAYLOAD"
ACTUAL_SHA="$(sha256sum "$PAYLOAD" | awk '{{print $1}}')"
[ "$ACTUAL_SHA" = "{expected_sha}" ] || {{ echo 'APC payload integrity check failed' >&2; exit 1; }}
tar -xzf "$PAYLOAD" -C "$PREFIX" --strip-components=1
rm -f "$PAYLOAD"
mkdir -p "$PREFIX/bin" "$PREFIX/data"
cat > "$PREFIX/bin/apc" <<'EOF'
#!/bin/sh
set -eu
ROOT=${{APC_INSTALL_PREFIX:-/opt/apc-enterprise}}
export PYTHONHOME="$ROOT/runtime"
export PYTHONPATH="$ROOT/runtime/lib/python3.13/site-packages${{PYTHONPATH:+:$PYTHONPATH}}"
export LD_LIBRARY_PATH="$ROOT/runtime/lib/x86_64-linux-gnu${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}"
export APC_DB_PATH="${{APC_DB_PATH:-$ROOT/data/apc-product.db}}"
exec "$ROOT/runtime/bin/python3.13" -m apc_product "$@"
EOF
chmod 0755 "$PREFIX/bin/apc"
"$PREFIX/bin/apc" status >/dev/null
printf '%s\\n' "APC Enterprise {VERSION} installed and locally verified at $PREFIX"
exit 0
__APC_PAYLOAD_START__
"""
        run.write_text(header, encoding="utf-8")
        result = subprocess.run(["base64", str(payload_path)], check=True, stdout=subprocess.PIPE)
        with run.open("ab") as fh:
            fh.write(result.stdout)
        run.chmod(0o755)
        shutil.rmtree(staging)
        return run

    def _build_oci_image(self, out: Path) -> Path:
        """Build a single-file OCI image archive without Docker/Podman."""
        if self._oci_image_cache and self._oci_image_cache.exists():
            target = out / self._oci_image_cache.name
            shutil.copy2(self._oci_image_cache, target)
            return target

        import json as json_module
        staging = self._cache_root / "oci-build"
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True)
        runtime_stage = staging / "runtime-stage"
        runtime_stage.mkdir()
        runtime = self._build_runtime_tree(runtime_stage)
        rootfs = staging / "rootfs"
        rootfs.mkdir()
        (rootfs / "opt" / "apc-enterprise").mkdir(parents=True, exist_ok=True)
        shutil.move(str(runtime), str(rootfs / "opt" / "apc-enterprise" / "runtime"))
        (rootfs / "var" / "lib" / "apc").mkdir(parents=True, exist_ok=True)
        (rootfs / "etc" / "ssl" / "certs").mkdir(parents=True, exist_ok=True)
        ca = Path("/etc/ssl/certs/ca-certificates.crt")
        if ca.exists():
            shutil.copy2(ca, rootfs / "etc" / "ssl" / "certs" / "ca-certificates.crt")
        (rootfs / "etc" / "passwd").write_text(
            "root:x:0:0:root:/root:/sbin/nologin\napc:x:10001:10001:APC Runtime:/var/lib/apc:/sbin/nologin\n",
            encoding="utf-8",
        )
        (rootfs / "etc" / "group").write_text("root:x:0:\napc:x:10001:\n", encoding="utf-8")
        (rootfs / "tmp").mkdir(exist_ok=True)
        os.chmod(rootfs / "tmp", 0o1777)
        os.chown(rootfs / "var" / "lib" / "apc", 10001, 10001)
        os.chown(rootfs / "tmp", 10001, 10001)

        layer_raw_path = staging / "layer.tar"
        with layer_raw_path.open("wb") as raw_fh, tarfile.open(fileobj=raw_fh, mode="w") as tf:
            for p in sorted(q for q in rootfs.rglob("*") if q.exists()):
                rel = p.relative_to(rootfs).as_posix()
                ti = tf.gettarinfo(str(p), arcname=rel)
                if rel == "var/lib/apc" or rel == "tmp":
                    ti.uid = 10001; ti.gid = 10001; ti.uname = "apc"; ti.gname = "apc"
                else:
                    ti.uid = 0; ti.gid = 0; ti.uname = "root"; ti.gname = "root"
                if ti.isreg():
                    with open(p, "rb") as fh:
                        tf.addfile(ti, fh)
                else:
                    tf.addfile(ti)
        diff_id = "sha256:" + sha256(layer_raw_path)
        layer_gz_path = staging / "layer.tar.gz"
        with layer_gz_path.open("wb") as compressed_fh:
            subprocess.run(["gzip", "-6", "-n", "-c", str(layer_raw_path)], stdout=compressed_fh, check=True)
        layer_digest = sha256(layer_gz_path)
        layer_size = layer_gz_path.stat().st_size
        raw_size = layer_raw_path.stat().st_size

        config = {
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "User": "10001:10001",
                "Env": [
                    "PYTHONHOME=/opt/apc-enterprise/runtime",
                    "PYTHONPATH=/opt/apc-enterprise/runtime/lib/python3.13/site-packages",
                    "LD_LIBRARY_PATH=/opt/apc-enterprise/runtime/lib/x86_64-linux-gnu",
                    "APC_MODE=PRODUCTION",
                    "APC_DB_PATH=/var/lib/apc/apc-product.db",
                ],
                "WorkingDir": "/var/lib/apc",
                "Entrypoint": [
                    "/opt/apc-enterprise/runtime/bin/python3.13",
                    "-m",
                    "apc_product",
                    "serve",
                    "--host",
                    "0.0.0.0",
                    "--port",
                    "8787",
                ],
            },
            "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        }
        config_bytes = json_module.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        config_digest = _hash_bytes(config_bytes)
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:" + config_digest,
                "size": len(config_bytes),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:" + layer_digest,
                    "size": layer_size,
                    "annotations": {"org.opencontainers.image.layer.compression": "gzip"},
                }
            ],
            "annotations": {
                "org.opencontainers.image.title": "APC Enterprise",
                "org.opencontainers.image.version": VERSION,
                "org.opencontainers.image.description": "APC distributed action security continuity runtime",
            },
        }
        manifest_bytes = json_module.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        manifest_digest = _hash_bytes(manifest_bytes)

        blobs = staging / "blobs" / "sha256"
        blobs.mkdir(parents=True)
        (staging / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}\n', encoding="utf-8")
        (staging / "index.json").write_text(
            json_module.dumps(
                {
                    "schemaVersion": 2,
                    "manifests": [
                        {
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": "sha256:" + manifest_digest,
                            "size": len(manifest_bytes),
                            "annotations": {"org.opencontainers.image.ref.name": f"apc-enterprise:{VERSION}"},
                        }
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (blobs / config_digest).write_bytes(config_bytes)
        (blobs / manifest_digest).write_bytes(manifest_bytes)
        shutil.copy2(layer_gz_path, blobs / layer_digest)
        (staging / "README.txt").write_text(
            f"APC Enterprise OCI image archive\nImage reference: apc-enterprise:{VERSION}\n"
            f"Uncompressed layer size: {raw_size} bytes\nCompressed layer size: {layer_size} bytes\n",
            encoding="utf-8",
        )

        archive = out / f"APC-Enterprise-{VERSION}-oci-image.tar"
        with tarfile.open(archive, mode="w") as tf:
            for rel_name in ["oci-layout", "index.json", "blobs", "README.txt"]:
                src = staging / rel_name
                tf.add(src, arcname=rel_name)
        cached = self._cache_root / archive.name
        shutil.copy2(archive, cached)
        self._oci_image_cache = cached
        shutil.rmtree(staging)
        return archive

    def _build_kubernetes_bundle(self, out: Path, *, openshift: bool) -> Path:
        staging = out / ".kubernetes-bundle"
        staging.mkdir()
        image_dir = staging / "image"
        chart_dir = staging / "chart"
        script_dir = staging / "bin"
        image_dir.mkdir(); chart_dir.mkdir(); script_dir.mkdir()
        image = self._build_oci_image(image_dir)
        image_name = image.name

        (chart_dir / "Chart.yaml").write_text(
            "apiVersion: v2\n"
            "name: apc-enterprise\n"
            "description: APC action security continuity runtime\n"
            "type: application\n"
            f"version: {VERSION}\n"
            f"appVersion: \"{VERSION}\"\n",
            encoding="utf-8",
        )
        (chart_dir / "values.yaml").write_text(
            f"image:\n  repository: apc-enterprise\n  tag: {VERSION}\n  pullPolicy: IfNotPresent\n"
            "replicaCount: 1\n"
            "service:\n  type: ClusterIP\n  port: 8787\n"
            "serviceAccount:\n  create: true\n"
            "podSecurityContext:\n  runAsNonRoot: true\n  seccompProfile:\n    type: RuntimeDefault\n"
            "containerSecurityContext:\n  allowPrivilegeEscalation: false\n  readOnlyRootFilesystem: true\n  capabilities:\n    drop: [ALL]\n"
            "persistence:\n  enabled: true\n  size: 1Gi\n"
            "resources:\n  requests:\n    cpu: 100m\n    memory: 128Mi\n  limits:\n    cpu: 1\n    memory: 512Mi\n",
            encoding="utf-8",
        )
        templates = chart_dir / "templates"
        templates.mkdir()
        (templates / "_helpers.tpl").write_text(
            '{{- define "apc-enterprise.name" -}}apc-enterprise{{- end -}}\n'
            '{{- define "apc-enterprise.fullname" -}}{{ include "apc-enterprise.name" . }}{{- end -}}\n'
            '{{- define "apc-enterprise.labels" -}}app.kubernetes.io/name: {{ include "apc-enterprise.name" . }}{{- end -}}\n',
            encoding="utf-8",
        )
        (templates / "serviceaccount.yaml").write_text(
            '{{- if .Values.serviceAccount.create }}\n'
            'apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: {{ include "apc-enterprise.fullname" . }}\n  labels:\n    {{- include "apc-enterprise.labels" . | nindent 4 }}\n'
            '{{- end }}\n',
            encoding="utf-8",
        )
        (templates / "pvc.yaml").write_text(
            '{{- if .Values.persistence.enabled }}\n'
            'apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata:\n  name: {{ include "apc-enterprise.fullname" . }}-data\nspec:\n  accessModes: ["ReadWriteOnce"]\n  resources:\n    requests:\n      storage: {{ .Values.persistence.size }}\n'
            '{{- end }}\n',
            encoding="utf-8",
        )
        (templates / "deployment.yaml").write_text(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: {{ include \"apc-enterprise.fullname\" . }}\n"
            "  labels:\n"
            "    {{- include \"apc-enterprise.labels\" . | nindent 4 }}\n"
            "spec:\n"
            "  replicas: {{ .Values.replicaCount }}\n"
            "  selector:\n"
            "    matchLabels:\n"
            "      app.kubernetes.io/name: {{ include \"apc-enterprise.name\" . }}\n"
            "  template:\n"
            "    metadata:\n"
            "      labels:\n"
            "        app.kubernetes.io/name: {{ include \"apc-enterprise.name\" . }}\n"
            "    spec:\n"
            "      serviceAccountName: {{ include \"apc-enterprise.fullname\" . }}\n"
            "      automountServiceAccountToken: false\n"
            "      securityContext:\n"
            "        {{- toYaml .Values.podSecurityContext | nindent 8 }}\n"
            "      containers:\n"
            "        - name: apc\n"
            "          image: \"{{ .Values.image.repository }}:{{ .Values.image.tag }}\"\n"
            "          imagePullPolicy: {{ .Values.image.pullPolicy }}\n"
            "          securityContext:\n"
            "            {{- toYaml .Values.containerSecurityContext | nindent 12 }}\n"
            "          ports:\n"
            "            - name: http\n"
            "              containerPort: 8787\n"
            "          env:\n"
            "            - name: APC_MODE\n"
            "              value: PRODUCTION\n"
            "            - name: APC_DB_PATH\n"
            "              value: /var/lib/apc/apc-product.db\n"
            "          volumeMounts:\n"
            "            - name: data\n"
            "              mountPath: /var/lib/apc\n"
            "          readinessProbe:\n"
            "            httpGet:\n"
            "              path: /readyz\n"
            "              port: http\n"
            "          livenessProbe:\n"
            "            httpGet:\n"
            "              path: /livez\n"
            "              port: http\n"
            "          resources:\n"
            "            {{- toYaml .Values.resources | nindent 12 }}\n"
            "      volumes:\n"
            "        - name: data\n"
            "          persistentVolumeClaim:\n"
            "            claimName: {{ include \"apc-enterprise.fullname\" . }}-data\n",
            encoding="utf-8",
        )
        (templates / "service.yaml").write_text(
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: {{ include \"apc-enterprise.fullname\" . }}\nspec:\n  type: {{ .Values.service.type }}\n  selector:\n    app.kubernetes.io/name: {{ include \"apc-enterprise.name\" . }}\n  ports:\n    - name: http\n      port: {{ .Values.service.port }}\n      targetPort: http\n",
            encoding="utf-8",
        )
        (templates / "networkpolicy.yaml").write_text(
            "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: {{ include \"apc-enterprise.fullname\" . }}\nspec:\n  podSelector:\n    matchLabels:\n      app.kubernetes.io/name: {{ include \"apc-enterprise.name\" . }}\n  policyTypes: [\"Ingress\", \"Egress\"]\n  ingress:\n    - from:\n        - podSelector:\n            matchLabels:\n              app.kubernetes.io/name: apc-enterprise\n  egress:\n    - to:\n        - namespaceSelector: {}\n          podSelector: {}\n      ports:\n        - protocol: UDP\n          port: 53\n",
            encoding="utf-8",
        )
        # Self-contained import/install helper. No credentials are embedded.
        (script_dir / "install.sh").write_text(
            f"""#!/bin/sh
set -eu
BUNDLE_DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")/..\" && pwd)\"
IMAGE=\"$BUNDLE_DIR/image/{image_name}\"
if command -v podman >/dev/null 2>&1; then
  podman load -i \"$IMAGE\"
elif command -v docker >/dev/null 2>&1; then
  echo \"Docker detected; use your approved OCI import workflow for: $IMAGE\" >&2
else
  echo \"No container runtime detected. Import the OCI image archive with the customer's approved runtime.\" >&2
fi
printf '%s\\n' \"Chart: $BUNDLE_DIR/chart\"
printf '%s\\n' \"Target profile: {'OpenShift' if openshift else 'Kubernetes'}\"
""",
            encoding="utf-8",
        )
        (script_dir / "install.sh").chmod(0o755)
        (staging / "README.md").write_text(
            f"""# APC Enterprise {VERSION} — {'OpenShift' if openshift else 'Kubernetes'} Customer Bundle

This is a **single customer delivery file** containing the APC OCI runtime image, Helm chart, and installation helper. It is not the APC development repository.

Image archive: `image/{image_name}`
Chart: `chart/`

The bundle is an engineering-evaluation delivery. The current APC product does not claim multi-instance HA merely because a Kubernetes cluster is available; the chart therefore defaults to one replica with customer-managed persistent storage. Multi-instance production HA requires the durable shared-state profile and its deployment evidence.

For restricted/air-gapped use, import the embedded OCI image into the customer-approved runtime on every required node or customer registry, then deploy the chart using the resulting image reference.
""",
            encoding="utf-8",
        )
        archive = out / f"APC-Enterprise-{VERSION}-{'openshift' if openshift else 'kubernetes'}-bundle.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(staging, arcname=f"APC-Enterprise-{VERSION}-{'openshift' if openshift else 'kubernetes'}-bundle")
        shutil.rmtree(staging)
        return archive

    def _third_party_notices(self) -> str:
        from importlib import metadata
        chunks = [
            f"APC Enterprise {VERSION}\n",
            "Third-party runtime dependencies bundled in customer-native offline artifacts.\n",
            "\n",
        ]
        for name in BUNDLED_DISTS:
            dist = metadata.distribution(name)
            license_expr = dist.metadata.get("License-Expression") or "See package license metadata"
            chunks.append(f"{dist.metadata.get('Name', name)} {dist.version} — {license_expr}\n")
        return "".join(chunks)

    # ---------- manifest ----------

    def _write_manifest(self, out: Path, intake: CustomerIntake, artifact: Path) -> Path:
        artifacts = [
            {
                "path": str(artifact.relative_to(out)).replace("\\", "/"),
                "sha256": sha256(artifact),
                "size": artifact.stat().st_size,
            }
        ]
        manifest = {
            "product": PRODUCT,
            "version": VERSION,
            "delivery_status": "ENGINEERING_EVALUATION_CUSTOMER_ARTIFACT",
            "customer": {
                "customer_id": intake.customer_id,
                "deployment_profile": intake.deployment_profile,
                "environment": intake.environment,
                "region": intake.region,
            },
            "delivery": {
                "artifact_format": intake.resolved_artifact_format(),
                "artifact": str(artifact.relative_to(out)).replace("\\", "/"),
                "pdp": intake.pdp,
                "identity": intake.identity,
                "protected_sink": intake.protected_sink,
                "evidence_storage": intake.evidence_storage,
                "ha_required": intake.ha_required,
                "air_gapped": intake.air_gapped,
            },
            "customer_artifact_principle": "one-primary-native-artifact-per-intake",
            "development_repository_included": False,
            "credentials_included": False,
            "artifacts": artifacts,
            "runtime_prerequisites": {
                "oem": "CPython 3.13 Linux x86_64 wheel with tested dependency set embedded",
                "linux_native": "amd64 Linux with compatible glibc; private CPython 3.13 runtime embedded",
                "air_gapped": "amd64 Linux with compatible glibc; private CPython 3.13 runtime embedded; install requires no network",
                "oci": "Linux amd64 OCI image; import into customer-approved OCI runtime/registry",
                "kubernetes": "Kubernetes/OpenShift cluster plus customer-approved container runtime/registry",
            },
            "bundled_runtime_dependencies": [
                {"name": d, "version": __import__("importlib.metadata", fromlist=["version"]).version(d)}
                for d in BUNDLED_DISTS
            ],
            "security_boundary": "Customer identity, PDP, KMS/HSM, protected-provider credentials and private keys remain customer-controlled and external to the artifact.",
            "claims": {
                "production_certified": False,
                "oem_certified": False,
                "independent_security_review": False,
            },
        }
        manifest_path = out / "customer-delivery-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return manifest_path


def sysconfig_path(name: str) -> str:
    import sysconfig
    return sysconfig.get_path(name)
