from __future__ import annotations
from pathlib import Path
from imgforensics.models import Finding, Severity, Status


def c2pa(path: Path, image) -> list[Finding]:
    data = path.read_bytes()
    markers = []
    for needle, label in ((b"c2pa", "C2PA marker"), (b"jumb", "JUMBF marker"), (b"manifest", "manifest text")):
        offset = data.lower().find(needle)
        if offset >= 0: markers.append({"marker": label, "offset": offset})
    if markers:
        return [Finding(finding="Candidate provenance markers present; cryptographic validation not performed", category="provenance", status=Status.POSSIBLE, severity=Severity.INFO, confidence=0.6, evidence=markers, method="read-only byte marker scan", limitations=["A marker is not a validated C2PA manifest.", "Signature, certificate chain, claim binding, and trust status require a standards-compliant validator."])]
    return [Finding(finding="No C2PA/JUMBF marker detected", category="provenance", status=Status.NOT_DETECTED, severity=Severity.INFO, confidence=0.9, evidence=[], method="read-only byte marker scan", limitations=["C2PA absence does not mean fake or manipulated."])]
