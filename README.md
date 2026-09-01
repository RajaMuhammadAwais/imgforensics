# imgforensics

`imgforensics` is an offline-first, evidence-oriented digital image forensics CLI. It is designed to answer **what measurable evidence can be established**, not whether an image is “real.” Every conclusion carries a status, confidence, method, and limitations.

## Installation

```bash
pip install -e .
imgforensics image sample.jpg
imgforensics image sample.jpg --all --json report.json --html report.html --sarif findings.sarif
imgforensics batch ./evidence --output ./case
```

## Current implementation

The initial implementation provides a format-agnostic pipeline with bounded decoding, cryptographic hashes, extension/magic/decoder identity, EXIF and GPS presence checks, read-only embedded-signature scanning, JPEG quantization and controlled recompression measurements, descriptive pixel statistics, an explicitly experimental AI-indicator measurement, JSON/HTML/SARIF output, chain-of-custody metadata, and batch manifest generation. Unsupported or malformed inputs become structured findings rather than uncaught crashes.

| Area | Behavior | Evidentiary caveat |
|---|---|---|
| Identity | Extension, magic bytes, decoder format, dimensions, frames | Filename and metadata are not authoritative |
| Integrity | MD5, SHA-1, SHA-256, SHA-512 | Hashes identify bytes; they do not establish authorship |
| Metadata | EXIF and GPS presence | Metadata may be stripped, copied, or rewritten |
| Structure | Embedded ZIP/PDF/PE/ELF signatures and JPEG trailing bytes | Signatures are reported at offsets; nothing is executed |
| JPEG | Quantization and recompression error | ELA and quality estimates are not standalone proof |
| Pixels | Entropy, moments, channel correlation | Descriptive statistics require contextual comparison |
| AI indicators | Experimental residual/color statistic | No definitive AI detection is claimed |

## Forensic stance

The design follows published forensic practice: source image forensics spans multiple tasks and has known generalization limits [1]. JPEG double-compression analysis is a recognized method based on DCT statistics, but performance depends on image complexity and compression quality [2]. Chain-of-custody records should document evidence handling, timestamps, and transfer purposes [3], while evidence must remain preserved and uncompromised throughout handling [4].

> The absence of a detected indicator does not prove authenticity, and the presence of an indicator does not by itself prove intentional manipulation.

## Security and privacy

The tool reads files locally, performs no network requests, does not execute embedded objects, applies a pixel budget, and catches decoder exceptions at analyzer boundaries. GPS values are not emitted by default; only presence is reported. This project is an analysis aid and should not be treated as a validated forensic instrument without laboratory testing, known-answer tests, and jurisdiction-specific review.

## Research references

[1]: https://pmc.ncbi.nlm.nih.gov/articles/PMC8321025/ “A Survey of Deep Learning-Based Source Image Forensics”
[2]: https://nij.ojp.gov/library/publications/method-detect-jpeg-based-double-compression “A Method to Detect JPEG-Based Double Compression”
[3]: https://csrc.nist.gov/glossary/term/chain_of_custody “NIST chain of custody”
[4]: https://www.nist.gov/forensic-science/interdisciplinary-topics/evidence-management “NIST Evidence Management”
