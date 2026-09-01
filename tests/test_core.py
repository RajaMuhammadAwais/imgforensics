from pathlib import Path
from PIL import Image
from imgforensics.core.pipeline import analyze
from imgforensics.analyzers.builtin import metadata, pixels, structure, jpeg
from imgforensics.core.pipeline import Analyzer

def analyzers():
    return [Analyzer("metadata", "metadata", metadata), Analyzer("structure", "security", structure), Analyzer("compression", "compression", jpeg), Analyzer("pixel", "pixel", pixels)]

def test_report_is_reproducible(tmp_path: Path):
    p = tmp_path / "sample.png"; Image.new("RGB", (16, 16), (10, 20, 30)).save(p)
    a = analyze(p, analyzers()); b = analyze(p, analyzers())
    assert a.hashes == b.hashes
    assert a.file["format"] == "PNG"
    assert all(0 <= f.confidence <= 1 for f in a.findings)

def test_extension_mismatch(tmp_path: Path):
    p = tmp_path / "photo.jpg"; Image.new("RGB", (8, 8), "red").save(p, format="PNG")
    report = analyze(p, analyzers())
    assert any("extension" in f.finding.lower() for f in report.findings)

def test_pixel_budget(tmp_path: Path):
    p = tmp_path / "large.png"; Image.new("RGB", (32, 32), "black").save(p)
    report = analyze(p, analyzers(), max_pixels=10)
    assert any(f.status.value == "UNSUPPORTED" for f in report.findings)
