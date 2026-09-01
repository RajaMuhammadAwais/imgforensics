# imgforensics CLI — Step-by-Step Ubuntu Guide

This guide is based on the current `RajaMuhammadAwais/imgforensics` source, its tests, and primary or official references. The tool reports **measurable observations**; it does not classify an image as simply “real” or “fake.” Image-forensics methods depend on context, post-processing, image complexity, and evaluation data [1] [2].

> **Forensic principle:** Preserve the original in its native format, analyze a verified working copy, and record fixity hashes. The OSAC guide distinguishes primary/original, backup, and working images and recommends documenting processing steps [3].

## 1. Install on Ubuntu

The project requires Python 3.10 or newer. Its `pyproject.toml` declares Pillow, NumPy, Typer, and Rich as runtime dependencies.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git

git clone https://github.com/RajaMuhammadAwais/imgforensics.git
cd imgforensics
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
```

Verify the installation:

```bash
imgforensics --help
python -m pytest -q
```

The current repository test suite passes with `3 passed`. In each new shell, activate the environment again with `source .venv/bin/activate`.

## 2. Preserve the evidence

Do not edit, resize, recompress, or clean metadata from the original. Use a working copy:

```bash
mkdir -p case-001/{original,working,reports}
cp --preserve=all /path/to/photo.jpg case-001/original/
sha256sum case-001/original/photo.jpg | tee case-001/original/photo.jpg.sha256
cp --preserve=all case-001/original/photo.jpg case-001/working/
sha256sum -c case-001/original/photo.jpg.sha256
```

`OK` means that the working copy has the same bytes as the recorded original. A hash establishes byte identity/fixity; it does not establish authorship or authenticity [3].

## 3. Analyze one image

```bash
imgforensics image case-001/working/photo.jpg
```

When no module flag is supplied, the CLI runs all built-in analyzers. Terminal output includes the decoded format, byte size, SHA-256, finding count, status, severity, confidence, and method.

The equivalent command name is also available:

```bash
imgforensics analyze case-001/working/photo.jpg
```

## 4. Generate all report formats

```bash
imgforensics image case-001/working/photo.jpg \
  --all \
  --json case-001/reports/report.json \
  --html case-001/reports/report.html \
  --sarif case-001/reports/findings.sarif \
  --analyst "Analyst Name" \
  --case-id "case-001" \
  --no-terminal
```

| File | Purpose |
|---|---|
| `report.json` | Complete structured report with hashes, findings, case metadata, and evidence graph |
| `report.html` | Self-contained human-readable rendering |
| `findings.sarif` | SARIF 2.1.0 output for CI/security tooling |

Use `--output` to create a case directory and default reports automatically:

```bash
imgforensics image case-001/working/photo.jpg --all --output case-001/reports
```

This creates `report.json`, `report.html`, and `case.json`. Explicit `--json`, `--html`, or `--sarif` paths take precedence.

## 5. CLI flags

| Flag | Behavior | Interpretation / limitation |
|---|---|---|
| `--all` | Run every built-in analyzer | Not an authenticity verdict |
| `--deep` | Alias for `--all` | Compatibility/readability alias |
| `--metadata` | Inspect EXIF and GPS presence | Metadata can be copied, stripped, or rewritten |
| `--structure` | Scan for embedded ZIP/PDF/PE/ELF signatures and JPEG trailing bytes | Signatures are read-only; hits can be coincidental |
| `--compression` | Measure JPEG quantization tables and controlled quality-95 recompression error | Quality estimate is heuristic; ELA is not standalone proof |
| `--pixel` | Measure entropy, RGB mean/std, and channel correlation | Descriptive statistics need contextual comparison |
| `--ai` | Run the explicitly experimental residual/color statistic | Not a trained classifier; false positives/negatives are possible |
| `--provenance` | Scan for candidate C2PA/JUMBF byte markers | A marker is not validated signature or trusted provenance |
| `--max-pixels N` | Bound decoded pixels; default is `50000000` | Limits memory exposure for large/untrusted inputs |
| `--json PATH` | Write a JSON report | Parent directory is created automatically |
| `--html PATH` | Write an HTML report | Convenience view, not a legal conclusion |
| `--sarif PATH` | Write SARIF 2.1.0 findings | Ingestible by compatible CI/security tools |
| `--output DIR` | Create a case directory and default reports | Existing output files may be overwritten |
| `--analyst TEXT` | Store an analyst label in case metadata | Does not authenticate the analyst |
| `--case-id TEXT` | Store the supplied case ID in the report | Maintain uniqueness in your case system |
| `--no-terminal` | Suppress terminal output | Useful for automation |
| `--strict` | Exit with code `2` if any HIGH or MEDIUM finding exists | A trigger for review, not a guilt finding |

Run one selected module:

```bash
imgforensics image photo.jpg --metadata --json metadata.json
imgforensics image photo.jpg --structure --json structure.json
imgforensics image photo.jpg --compression --json jpeg.json
imgforensics image photo.jpg --pixel --json pixels.json
imgforensics image photo.jpg --provenance --json provenance.json
```

If no module flag is supplied, all modules run. If one or more module flags are supplied, only those selected modules run.

## 6. Batch analysis

Analyze all regular files recursively:

```bash
imgforensics batch case-001/working --output case-001/reports/batch
```

Expected outputs:

```text
case-001/reports/batch/manifest.csv
case-001/reports/batch/<filename>.json
```

`manifest.csv` contains the input path, SHA-256, decoded format, and an error column. A malformed file is recorded as a row-level error instead of terminating the entire batch.

## 7. Verify the reports

```bash
python3 -m json.tool case-001/reports/report.json >/dev/null && echo 'JSON OK'
python3 -m json.tool case-001/reports/findings.sarif >/dev/null && echo 'SARIF JSON OK'
head -n 2 case-001/reports/report.html
sha256sum case-001/working/photo.jpg
```

Important report fields:

| Field | Meaning |
|---|---|
| `hashes.sha256` | Fixity identity of the analyzed bytes |
| `file.format` / `file.magic_format` | Decoder and magic-byte observations rather than filename trust |
| `findings[].status` | Conservative state such as `DETECTED`, `POSSIBLE`, `INCONCLUSIVE`, or `EXPERIMENTAL` |
| `findings[].confidence` | Confidence attached to the method/finding, not probability of authenticity |
| `findings[].method` | The measurable procedure used |
| `findings[].limitations` | Known boundaries of the observation |
| `case` | Timestamp, analyst, platform, enabled modules, and analysis context |
| `evidence_graph` | Serializable relationships between the asset and findings; not a truth claim |

## 8. How to interpret findings

**EXIF/GPS present** means only that tags were found. It does not prove camera ownership or location. **Extension mismatch** is an anomaly worth reviewing, but benign renaming and conversion workflows can produce it. **Embedded signatures** are not executed; the current implementation performs only a read-only byte scan.

JPEG analysis reports quantization tables and recompression error. Published double-compression research uses DCT-derived features and classifier evaluation, and shows that performance changes with image complexity and compression quality [2]. This repository’s quality estimate is heuristic and must not be presented as a published detector or standalone proof.

C2PA defines separate manifest states including well-formed, valid, and trusted. A raw `c2pa` or `jumbf` marker is not cryptographic validation [4]. The current `--provenance` implementation intentionally stops at candidate-marker scanning and does not claim signature, certificate-chain, or trust validation.

## 9. Reproducible investigation checklist

1. Preserve the original and record its initial SHA-256.
2. Create a hash-verified working copy.
3. Record the tool version, Python version, operating system, analyst, and case ID.
4. Run the all-module report first, then create targeted module reports as needed.
5. Store JSON and SARIF in controlled case storage; treat HTML as a convenience view.
6. Review every `POSSIBLE`, `DETECTED`, and `EXPERIMENTAL` result against independent contextual evidence.
7. If processing is performed, do not overwrite the original; document each step, setting, and output hash.
8. Make legal or court conclusions only under a trained examiner, validated SOP, known-answer testing, and applicable jurisdictional requirements.

## 10. Security and scope

The tool is designed to run locally/offline: it does not upload images or make network requests, does not execute embedded objects, and uses bounded decoding. Nevertheless, run untrusted files in an isolated Ubuntu environment. Do not delete original data, handle generated reports as untrusted HTML, and follow the project security policy.

This project is **not a validated forensic instrument** without laboratory validation, known-answer datasets, detector/version tracking, reproducibility checks, and jurisdiction-specific review. The OSAC guide also states that professional judgment, training, and discipline-specific knowledge are not replaced by the guide [3].

ExifTool is a reputable independent metadata command-line tool, but the current `imgforensics` implementation uses Pillow-based EXIF inspection. ExifTool can be installed as an optional cross-check; it is not a hidden dependency of this project [5].

## References

[1]: https://pmc.ncbi.nlm.nih.gov/articles/PMC8321025/ "A Survey of Deep Learning-Based Source Image Forensics"
[2]: https://nij.ojp.gov/library/publications/method-detect-jpeg-based-double-compression "A Method to Detect JPEG-Based Double Compression"
[3]: https://www.nist.gov/document/osac-2024-n-0011-standard-guide-forensic-digital-image-management-version-10 "OSAC 2024-N-0011 Standard Guide for Forensic Digital Image Management"
[4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/ContentCredentials.html "C2PA Content Credentials Specification 2.4"
[5]: https://exiftool.org/ "ExifTool by Phil Harvey"
