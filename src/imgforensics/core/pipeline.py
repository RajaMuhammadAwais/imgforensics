from __future__ import annotations

import hashlib
import mimetypes
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from PIL import Image, UnidentifiedImageError

from imgforensics.models import Finding, Report, Severity, Status

MAGIC = {
    b"\xff\xd8\xff": ("JPEG", "image/jpeg"), b"\x89PNG\r\n\x1a\n": ("PNG", "image/png"),
    b"GIF87a": ("GIF", "image/gif"), b"GIF89a": ("GIF", "image/gif"),
    b"BM": ("BMP", "image/bmp"), b"RIFF": ("RIFF container", "image/webp"),
    b"II*\x00": ("TIFF", "image/tiff"), b"MM\x00*": ("TIFF", "image/tiff"),
}

class Analyzer:
    def __init__(self, name: str, category: str, fn: Callable[[Path, Image.Image | None], list[Finding]]):
        self.name, self.category, self.fn = name, category, fn

    def run(self, path: Path, image: Image.Image | None) -> list[Finding]:
        try:
            return self.fn(path, image)
        except Exception as exc:  # untrusted input must not crash the case
            return [Finding(f"{self.name} failed safely", self.category, Status.INCONCLUSIVE,
                            Severity.MEDIUM, 1.0, [repr(exc)], "exception boundary",
                            ["Parser or decoder rejected the input; no conclusion was made."])]

def hashes(path: Path) -> dict[str, str]:
    data = path.read_bytes()
    return {name: hashlib.new(name, data).hexdigest() for name in ("md5", "sha1", "sha256", "sha512")}

def identify(path: Path, max_pixels: int = 50_000_000) -> tuple[dict, Image.Image | None, list[Finding]]:
    raw = path.read_bytes()
    magic_name, magic_mime = "UNKNOWN", "application/octet-stream"
    for signature, value in MAGIC.items():
        if raw.startswith(signature): magic_name, magic_mime = value; break
    guessed_mime = mimetypes.guess_type(path.name)[0] or "unknown"
    findings: list[Finding] = []
    image = None
    try:
        with Image.open(path) as probe:
            width, height = probe.size
            info = {"extension": path.suffix.lower(), "mime_guess": guessed_mime,
                    "magic_format": magic_name, "magic_mime": magic_mime,
                    "format": probe.format, "size_bytes": path.stat().st_size,
                    "dimensions": [width, height], "mode": probe.mode,
                    "frames": getattr(probe, "n_frames", 1), "animated": getattr(probe, "is_animated", False)}
            if width * height > max_pixels:
                findings.append(Finding("Pixel budget exceeded", "security", Status.UNSUPPORTED, Severity.HIGH, 1.0,
                    [f"{width}x{height} > {max_pixels} pixels"], "bounded decode", ["Image pixels were not decoded."]))
            else:
                image = probe.copy(); image.format = probe.format
            if path.suffix.lower().lstrip(".") not in {str(probe.format).lower(), "jpg" if probe.format == "JPEG" else ""}:
                findings.append(Finding("Filename extension differs from decoded format", "identity", Status.DETECTED, Severity.MEDIUM, 1.0,
                    [path.suffix.lower(), probe.format], "Pillow decoder plus magic bytes", ["Extension alone is not proof of content."]))
    except (UnidentifiedImageError, OSError) as exc:
        info = {"extension": path.suffix.lower(), "mime_guess": guessed_mime,
                "magic_format": magic_name, "magic_mime": magic_mime,
                "size_bytes": path.stat().st_size, "decode": "failed"}
        findings.append(Finding("Image format detected but decoder support is unavailable or input is malformed",
            "identity", Status.UNSUPPORTED, Severity.MEDIUM, [repr(exc)], "magic-byte scan and bounded decoder", []))
    return info, image, findings

def make_case(path: Path, file_hashes: dict[str, str], modules: list[str], artifacts: list[str], started: float) -> dict:
    return {"case_id": hashlib.sha256((str(path.resolve()) + file_hashes["sha256"]).encode()).hexdigest()[:16],
            "analyst": "unspecified", "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "original_filename": path.name, "sha256": file_hashes["sha256"],
            "tool_version": "0.1.0", "python": sys.version, "os": platform.platform(),
            "enabled_modules": modules, "analysis_duration_seconds": round(time.time() - started, 4),
            "generated_artifacts": artifacts}

def analyze(path: Path, analyzers: list[Analyzer], max_pixels: int = 50_000_000) -> Report:
    started = time.time(); file_info, image, findings = identify(path, max_pixels); file_hashes = hashes(path)
    for analyzer in analyzers: findings.extend(analyzer.run(path, image))
    case = make_case(path, file_hashes, [a.name for a in analyzers], [], started)
    return Report(file_info, file_hashes, findings, case)
