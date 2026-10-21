# Security

VPNer handles VPN credentials and decides where your traffic goes, so leaks and credential exposure are treated as security problems.

## Reporting

Please **do not open a public issue** for a vulnerability or a leak. Report it privately on GitHub: the **Security** tab of the repository → **Report a vulnerability** ([direct link](../../security/advisories/new)). Only the author sees the report. Include:

- what happens and what you expected;
- the version (Settings shows it, or `vpner.exe version`) and Windows version;
- the connection types involved (no keys or passwords, please);
- steps to reproduce, if you have them.

You will get an answer as soon as possible; fixed issues are mentioned in the [changelog](CHANGELOG.md).

## What is in scope

- traffic or DNS going around the chosen VPN, or going out directly when a VPN is down;
- the kill switch not blocking, or not being removed when it should;
- passwords, keys or tokens being stored or sent in the clear, or reachable by other local programs;
- the local interface or API being reachable from other origins or users.

The project is an early beta written entirely by an AI model and has not been audited — see [Project status](README.md#project-status).
