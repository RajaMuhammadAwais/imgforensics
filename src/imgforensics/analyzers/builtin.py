from __future__ import annotations

import io
from pathlib import Path
import numpy as np
from PIL import Image, ExifTags
from imgforensics.models import Finding, Severity, Status


def metadata(path: Path, image: Image.Image | None) -> list[Finding]:
    if image is None:
        return [Finding(finding="Metadata unavailable", category="metadata", status=Status.UNSUPPORTED, severity=Severity.INFO, confidence=1.0, method="bounded decode")]
    exif = image.getexif(); names = {ExifTags.TAGS.get(k, str(k)): v for k, v in exif.items()}; gps = "GPSInfo" in names
    return [Finding(finding="EXIF metadata present" if names else "EXIF metadata not present", category="metadata", status=Status.DETECTED if names else Status.NOT_DETECTED, severity=Severity.INFO, confidence=1.0, evidence=list(names.keys()), method="Pillow EXIF directory inspection", limitations=["Metadata can be stripped, rewritten, or copied."]),
        Finding(finding="GPS metadata present" if gps else "GPS metadata not present", category="metadata", status=Status.DETECTED if gps else Status.NOT_DETECTED, severity=Severity.MEDIUM if gps else Severity.INFO, confidence=1.0, evidence=["GPSInfo"] if gps else [], method="EXIF tag inspection", limitations=["Absence of GPS does not establish location or authenticity."])]

def pixels(path: Path, image: Image.Image | None) -> list[Finding]:
    if image is None: return []
    arr = np.asarray(image.convert("RGB"), dtype=np.float32) / 255.0; gray = arr.mean(axis=2); hist, _ = np.histogram(gray, bins=256, range=(0,1), density=True); p = hist / max(hist.sum(), 1e-12); entropy = float(-(p[p>0] * np.log2(p[p>0])).sum()); corr = np.corrcoef(arr.reshape(-1, 3).T)
    return [Finding(finding="Pixel statistics measured", category="pixel", status=Status.DETECTED, severity=Severity.INFO, confidence=1.0, evidence={"entropy_bits": round(entropy, 5), "mean_rgb": arr.mean((0,1)).round(5).tolist(), "std_rgb": arr.std((0,1)).round(5).tolist(), "channel_correlation": np.nan_to_num(corr).round(5).tolist()}, method="256-bin grayscale histogram and RGB moments", limitations=["Statistics are descriptive and not proof of editing."])]

def structure(path: Path, image: Image.Image | None) -> list[Finding]:
    data = path.read_bytes(); signatures = {b"PK\x03\x04": "ZIP", b"%PDF": "PDF", b"MZ": "PE/Windows", b"\x7fELF": "ELF"}; hits = []
    for sig, label in signatures.items():
        start = 0
        while True:
            i = data.find(sig, start)
            if i < 0: break
            hits.append({"signature": label, "offset": i}); start = i + 1
    trailing = []
    if image and image.format == "JPEG":
        eoi = data.rfind(b"\xff\xd9")
        if eoi >= 0 and eoi + 2 < len(data): trailing.append({"offset": eoi+2, "bytes": len(data)-eoi-2})
    findings = [Finding(finding="Suspicious embedded signatures located" if hits else "No embedded executable/archive signatures located", category="security", status=Status.POSSIBLE if hits else Status.NOT_DETECTED, severity=Severity.HIGH if hits else Severity.INFO, confidence=0.75 if hits else 1.0, evidence=hits, method="read-only byte signature scan", limitations=["Signatures can be coincidental; objects are never executed."])]
    if trailing: findings.append(Finding(finding="Data appended after JPEG end marker", category="structure", status=Status.DETECTED, severity=Severity.MEDIUM, confidence=1.0, evidence=trailing, method="JPEG marker boundary scan", limitations=["Trailing data may be benign application data."]))
    return findings

def jpeg(path: Path, image: Image.Image | None) -> list[Finding]:
    if image is None or image.format != "JPEG": return [Finding(finding="JPEG-specific analysis not applicable", category="compression", status=Status.UNSUPPORTED, severity=Severity.INFO, confidence=1.0, method="decoded format gate")]
    qtables = getattr(image, "quantization", {}) or {}; qualities = [round(100 - (sum(table)/len(table) - 1) * 0.5, 1) for table in qtables.values()]; buf = io.BytesIO(); image.save(buf, format="JPEG", quality=95); decoded = np.asarray(image.convert("RGB"), dtype=np.int16); recompressed = np.asarray(Image.open(io.BytesIO(buf.getvalue())).convert("RGB"), dtype=np.int16); mae = float(np.abs(decoded-recompressed).mean())
    return [Finding(finding="JPEG quantization tables measured", category="compression", status=Status.DETECTED, severity=Severity.INFO, confidence=1.0, evidence={"table_count": len(qtables), "estimated_quality_heuristic": qualities, "recompression_mae": round(mae, 4)}, method="JPEG quantization inspection and quality-95 recompression comparison", limitations=["Quality estimates are heuristic; recompression error is not proof of manipulation."]), Finding(finding="Traditional JPEG ELA completed; interpretation requires context", category="pixel", status=Status.INCONCLUSIVE, severity=Severity.INFO, confidence=1.0, evidence={"recompression_quality": 95, "mean_absolute_error": round(mae, 4)}, method="controlled recompression error analysis", limitations=["ELA is not a standalone authenticity test."])]

def ai_indicators(path: Path, image: Image.Image | None) -> list[Finding]:
    if image is None: return []
    arr = np.asarray(image.convert("RGB"), dtype=np.float32)/255; local = float(arr.std(axis=2).mean())
    return [Finding(finding="Experimental AI-generation indicators measured", category="ai", status=Status.EXPERIMENTAL, severity=Severity.INFO, confidence=0.5, evidence={"mean_local_channel_std": round(local, 6)}, method="descriptive residual/color statistic; no trained classifier", limitations=["AI detection is probabilistic and may produce false positives and false negatives.", "This measurement cannot identify a generator or establish authenticity."])]
