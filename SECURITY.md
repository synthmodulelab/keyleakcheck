# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems.

Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on this repository. You will get an acknowledgement within 72 hours and a status update at least weekly until the issue is resolved.

Please include what you found, how to reproduce it, and the version (`npx keyleakcheck --version`).

## Supported versions

Only the latest release receives security fixes.

## Design guarantees

Key Leak Check reads files that contain secrets, so it is built around a small set of guarantees. A change that weakens any of them is treated as a security bug.

1. **No network access.** Shipped code imports no network or process-spawning module and does not call `fetch`. At startup, `fetch` is replaced with a function that throws.
2. **Read-only.** Shipped code calls no filesystem write API.
3. **No full secrets in output.** Every output format prints keys masked. Findings are identified by a truncated SHA-256 fingerprint.
4. **Zero dependencies.** No runtime dependencies and no install scripts, so nothing third-party runs on your machine.
5. **Reproducible, attested releases.** Packages are built and published only by the release workflow in this repository, with npm provenance, a GitHub artifact attestation and a published SHA-256 checksum.

Guarantees 1 to 4 are enforced by `test/guarantees.test.js` and `test/scan.test.js`, which run on every push and pull request.

## Threat model

| Threat | Mitigation |
| --- | --- |
| The tool sends secrets somewhere | No network code; static test; `fetch` tripwire; no dependencies that could add network code |
| The tool damages or alters files | No write APIs; static test; read-only snapshot test |
| Secrets end up in terminal logs, CI logs or screenshots | Masked output only; `--card` contains no keys and no paths |
| A malicious version is published (compromised maintainer account or token) | Publishing only from CI with provenance; maintainer 2FA; npm Trusted Publishing with no stored token, and token publishing disallowed on the package; users can verify provenance and attestations |
| Typosquatting (a look-alike package) | README and VERIFY.md name the one official package; maintainers watch npm for look-alikes and report them |
| A malicious contribution | Branch protection; required review; CI must pass, including the guarantee tests |
| Symlink tricks or loops | Symlinked directories inside scanned folders are never followed (a known agent folder that is itself a symlink is followed, once); symlinked files are only read, and their contents are printed masked like any other file |
| Very large files cause a hang, or are silently skipped | Files are read in 16 MB chunks; files over the size limit, unreadable files and a reached file limit are always reported and mark the scan as partial (exit code 3) |
| Crafted file names inject terminal control sequences into the report | Control and bidirectional-override characters in printed paths are replaced with `?` |

## Out of scope

- Keys that do not match a known provider pattern.
- Checking whether a found key is still valid, or removing keys from files. These need network access or file writes, which this package will never have. If built, they will live in a separate, opt-in package (planned, not yet available) with its own published guarantees.
