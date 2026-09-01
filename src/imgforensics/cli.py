from __future__ import annotations
import csv, json
from pathlib import Path
import typer
from imgforensics.core.pipeline import Analyzer, analyze
from imgforensics.analyzers.builtin import metadata, pixels, structure, jpeg, ai_indicators
from imgforensics.reports.render import terminal, to_json, to_html, to_sarif

app = typer.Typer(add_completion=False, no_args_is_help=True)

def selected(all_modules: bool, metadata_on: bool, structure_on: bool, compression_on: bool, pixel_on: bool, ai_on: bool) -> list[Analyzer]:
    if all_modules or not any((metadata_on, structure_on, compression_on, pixel_on, ai_on)):
        return [Analyzer("metadata", "metadata", metadata), Analyzer("structure", "security", structure), Analyzer("compression", "compression", jpeg), Analyzer("pixel", "pixel", pixels), Analyzer("ai", "ai", ai_indicators)]
    result = []
    if metadata_on: result.append(Analyzer("metadata", "metadata", metadata))
    if structure_on: result.append(Analyzer("structure", "security", structure))
    if compression_on: result.append(Analyzer("compression", "compression", jpeg))
    if pixel_on: result.append(Analyzer("pixel", "pixel", pixels))
    if ai_on: result.append(Analyzer("ai", "ai", ai_indicators))
    return result

@app.command()
def image(path: Path = typer.Argument(..., exists=True, readable=True), deep: bool = typer.Option(False), all_modules: bool = typer.Option(False, "--all"), metadata_on: bool = typer.Option(False, "--metadata"), structure_on: bool = typer.Option(False, "--structure"), compression_on: bool = typer.Option(False, "--compression"), pixel_on: bool = typer.Option(False, "--pixel"), ai_on: bool = typer.Option(False, "--ai"), json_path: Path | None = typer.Option(None, "--json"), html_path: Path | None = typer.Option(None, "--html"), sarif_path: Path | None = typer.Option(None, "--sarif"), output: Path | None = typer.Option(None, "--output"), max_pixels: int = typer.Option(50_000_000, min=1)):
    if not path.is_file(): raise typer.BadParameter("path must be a regular file")
    report = analyze(path, selected(all_modules or deep, metadata_on, structure_on, compression_on, pixel_on, ai_on), max_pixels)
    if output:
        output.mkdir(parents=True, exist_ok=True); json_path = json_path or output / "report.json"; html_path = html_path or output / "report.html"; (output / "case.json").write_text(json.dumps(report.case, indent=2) + "\n")
    if json_path: to_json(report, json_path)
    if html_path: to_html(report, html_path)
    if sarif_path: to_sarif(report, sarif_path)
    typer.echo(terminal(report))

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
