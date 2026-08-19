# audits

Sample reports produced by rootward against real repositories. They are here so a reader
can see the output format before running the tool, not as a service offering.

| Report | Target | Commit | Date | Findings |
|---|---|---|---|---|
| [rootward-dstack-report.pdf](rootward-dstack-report.pdf) | dstack | `174d85819a94` | 19 Aug 2026 | 41 (13 critical, 21 high, 6 medium, 1 low) |

Scope for that run: application source across Rust, Go, Python, JavaScript and TypeScript,
container and deployment configuration, KMS key policy, OS and firmware build recipes,
and the built enclave image where one is present in the tree. Test data, mocks, simulators,
fixtures and vendored samples are excluded.

Static only. No live infrastructure was touched: no credentials were used, no attestation
was fetched from running hardware, and no deployed KMS policy was read. Every finding is a
claim about code at the commit above, and each carries its own `file:line` evidence plus the
list of what the run could not check.
