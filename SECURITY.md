# Security policy

kekkai is a sandbox, so a way for a sandboxed child to escape or bypass its
rules is a security vulnerability.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability
reporting: <https://github.com/Sannrox/kekkai/security/advisories/new>.
Do not open a public issue, pull request, or discussion.

Please include the kernel version, the backend and settings used, and a
minimal reproduction. In scope are, for example: writing or reading outside
the allowed paths, creating network sockets under `linux_native`, exceeding
configured limits, or a backend silently downgrading.

We aim to acknowledge reports within a week and to publish a fix and an
advisory before the details become public.

## Supported versions

kekkai has no releases yet. Once it does, only the latest release receives
security fixes.
