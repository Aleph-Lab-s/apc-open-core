# GitHub Actions smoke check

The root `action.yml` makes this repository structurally eligible to be considered as a GitHub Action. It runs a local APC package smoke check (`apc doctor`, integration catalog and evidence verification) in DEMO mode. It does not scan a caller's application, prove that external effects are mediated, or certify an APC deployment.

The action is not published on GitHub Marketplace. Before listing, verify the repository identity, action metadata, dependency pinning, release tags, 2FA and Marketplace terms. Consider splitting the action into a dedicated repository once the action's user value and stable compatibility contract are proven.
