# Contributing to imgforensics

Thank you for helping improve `imgforensics`. Contributions should strengthen reproducibility, evidentiary transparency, and safe handling of untrusted image files.

## Development workflow

Create a focused branch from the default branch, make a small logically complete change, add or update tests, and open a pull request with a clear explanation of the forensic method and its limitations. Do not include private evidence, personally identifying metadata, GPS data, or copyrighted samples in commits.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest -q
```

## Pull requests

A pull request should explain the user-visible behavior, cite relevant standards or research where a method is introduced, document unsupported cases, and include deterministic tests. Findings must never overstate certainty. New analyzers should use the structured `Finding` model and must fail safely on malformed input.

## Commit style

Use concise imperative subjects, for example `Add bounded pixel decoding` or `Document JPEG limitations`. Keep unrelated refactors separate from forensic-method changes.
