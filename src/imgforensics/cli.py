from __future__ import annotations
import csv, json
from pathlib import Path
import typer
from imgforensics.core.pipeline import Analyzer, analyze
from imgforensics.analyzers.builtin import metadata, pixels, structure, jpeg, ai_indicators
from imgforensics.analyzers.provenance import c2pa
from imgforensics.reports.render import terminal, to_json, to_html, to_sarif

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Offline image-forensics reports from the command line.")

@app.callback(invoke_without_command=True)
def main(version: bool = typer.Option(False, "--version", help="Show the installed version and exit.")):
    if version:
        typer.echo("imgforensics 0.1.0")
        raise typer.Exit()

def selected(all_modules: bool, metadata_on: bool, structure_on: bool, compression_on: bool, pixel_on: bool, ai_on: bool, provenance_on: bool = False) -> list[Analyzer]:
    if all_modules or not any((metadata_on, structure_on, compression_on, pixel_on, ai_on, provenance_on)):
        return [Analyzer("metadata", "metadata", metadata), Analyzer("structure", "security", structure), Analyzer("compression", "compression", jpeg), Analyzer("pixel", "pixel", pixels), Analyzer("ai", "ai", ai_indicators), Analyzer("provenance", "provenance", c2pa)]
    result = []
    if metadata_on: result.append(Analyzer("metadata", "metadata", metadata))
    if structure_on: result.append(Analyzer("structure", "security", structure))
    if compression_on: result.append(Analyzer("compression", "compression", jpeg))
    if pixel_on: result.append(Analyzer("pixel", "pixel", pixels))
    if ai_on: result.append(Analyzer("ai", "ai", ai_indicators))
    if provenance_on: result.append(Analyzer("provenance", "provenance", c2pa))
    return result

@app.command()
def image(path: Path = typer.Argument(..., exists=True, readable=True), deep: bool = typer.Option(False, "--deep", help="Alias for --all."), all_modules: bool = typer.Option(False, "--all", help="Run every built-in analyzer."), metadata_on: bool = typer.Option(False, "--metadata", help="Run metadata and GPS-presence checks."), structure_on: bool = typer.Option(False, "--structure", help="Run read-only embedded-signature checks."), compression_on: bool = typer.Option(False, "--compression", help="Run JPEG quantization/recompression checks."), pixel_on: bool = typer.Option(False, "--pixel", help="Run descriptive pixel statistics."), ai_on: bool = typer.Option(False, "--ai", help="Run explicitly experimental AI-indicator statistic."), provenance_on: bool = typer.Option(False, "--provenance", help="Scan for candidate C2PA/JUMBF markers only."), json_path: Path | None = typer.Option(None, "--json", "-j", help="Write a JSON report."), html_path: Path | None = typer.Option(None, "--html", help="Write a self-contained HTML report."), sarif_path: Path | None = typer.Option(None, "--sarif", help="Write SARIF 2.1.0 findings."), output: Path | None = typer.Option(None, "--output", "-o", help="Create a case directory and default report files."), max_pixels: int = typer.Option(50_000_000, "--max-pixels", min=1, help="Bound decoded pixels to protect memory."), analyst: str = typer.Option("unspecified", "--analyst", help="Analyst label stored in case metadata."), case_id: str | None = typer.Option(None, "--case-id", help="Optional case identifier stored in case metadata."), no_terminal: bool = typer.Option(False, "--no-terminal", help="Suppress terminal output."), strict: bool = typer.Option(False, "--strict", help="Exit 2 if any HIGH or MEDIUM finding is present.")):
    if not path.is_file(): raise typer.BadParameter("path must be a regular file")
    report = analyze(path, selected(all_modules or deep, metadata_on, structure_on, compression_on, pixel_on, ai_on, provenance_on), max_pixels)
    report.case["analyst"] = analyst
    if case_id:
        report.case["case_id"] = case_id
    if output:
        output.mkdir(parents=True, exist_ok=True); json_path = json_path or output / "report.json"; html_path = html_path or output / "report.html"; (output / "case.json").write_text(json.dumps(report.case, indent=2) + "\n")
    if json_path: to_json(report, json_path)
    if html_path: to_html(report, html_path)
    if sarif_path: to_sarif(report, sarif_path)
    if not no_terminal:
        typer.echo(terminal(report))
    if strict and any(f.severity.value in {"HIGH", "MEDIUM"} for f in report.findings):
        raise typer.Exit(code=2)

@app.command("scan", help="Easy mode: scan one image and save JSON, HTML, and case metadata.")
def scan(path: Path = typer.Argument(..., exists=True, readable=True, help="Image file to scan."), output: Path | None = typer.Option(None, "--output", "-o", help="Output folder (default: ./case/<image-name>)."), analyst: str = typer.Option("unspecified", "--analyst", help="Analyst label."), case_id: str | None = typer.Option(None, "--case-id", help="Optional case ID."), max_pixels: int = typer.Option(50_000_000, "--max-pixels", min=1, help="Maximum decoded pixels.")):
    destination = output or Path("case") / path.stem
    image(path, False, True, False, False, False, False, False, False, None, None, None, destination, max_pixels, analyst, case_id, False, False)

@app.command("analyze")
def analyze_command(path: Path = typer.Argument(..., exists=True, readable=True), deep: bool = typer.Option(False, "--deep"), all_modules: bool = typer.Option(False, "--all"), metadata_on: bool = typer.Option(False, "--metadata"), structure_on: bool = typer.Option(False, "--structure"), compression_on: bool = typer.Option(False, "--compression"), pixel_on: bool = typer.Option(False, "--pixel"), ai_on: bool = typer.Option(False, "--ai"), provenance_on: bool = typer.Option(False, "--provenance"), json_path: Path | None = typer.Option(None, "--json"), html_path: Path | None = typer.Option(None, "--html"), sarif_path: Path | None = typer.Option(None, "--sarif"), output: Path | None = typer.Option(None, "--output"), max_pixels: int = typer.Option(50_000_000, "--max-pixels", min=1), analyst: str = typer.Option("unspecified", "--analyst"), case_id: str | None = typer.Option(None, "--case-id"), no_terminal: bool = typer.Option(False, "--no-terminal"), strict: bool = typer.Option(False, "--strict")):
    return image(path, deep, all_modules, metadata_on, structure_on, compression_on, pixel_on, ai_on, provenance_on, json_path, html_path, sarif_path, output, max_pixels, analyst, case_id, no_terminal, strict)

@app.command()
def batch(directory: Path = typer.Argument(..., exists=True, file_okay=False), output: Path = typer.Option(Path("case"), "--output")):
    output.mkdir(parents=True, exist_ok=True); rows = []
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        try:
            report = analyze(path, selected(True, False, False, False, False, False))
            target = output / (path.name + ".json"); to_json(report, target); rows.append({"file": str(path), "sha256": report.hashes["sha256"], "format": report.file.get("format", "unknown")})
        except Exception as exc: rows.append({"file": str(path), "error": repr(exc)})
    with (output / "manifest.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["file", "sha256", "format", "error"]); writer.writeheader(); writer.writerows(rows)
    typer.echo(f"Analyzed {len(rows)} files; reports written to {output}")

if __name__ == "__main__": app()
