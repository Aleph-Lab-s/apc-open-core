# Deployment artefacts

`Dockerfile` builds the community alpha from source. The Helm chart is a single-replica evaluation profile only. It assumes a suitable image has been built and published by the deploying operator; this repository has not published an OCI image to GHCR.

The chart requires a Kubernetes Secret containing `APC_ADMIN_TOKEN` because its HTTP API is bound inside the pod. Create the secret out-of-band, do not put tokens in values.yaml, and restrict ingress/network access. The default mode is DEMO. Do not set production profile/mode; current production execution is explicitly blocked and the system is not HA.
