# Security Policy

## Scope

`imgforensics` processes untrusted image files. Security issues include parser crashes, uncontrolled memory or CPU use, path traversal, unsafe subprocess behavior, unintended network access, and execution or extraction of embedded objects.

## Reporting

Please do not publish an exploit or attach sensitive evidence to a public issue. Report privately through the repository’s GitHub security advisory mechanism when enabled, or contact the maintainers listed in the repository profile. Include the affected version, operating system, minimal reproducible input where safe, expected impact, and a proposed mitigation.

## User safety guidance

Run investigations in an isolated environment, preserve the original evidence, verify SHA-256 before and after handling, and avoid opening generated reports in environments that may execute active content. The project does not upload images or perform network requests by default.
