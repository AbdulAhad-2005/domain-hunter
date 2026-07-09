import csv
from collections import Counter
from pathlib import Path

from core.aggregator import AggregatedFinding

_HEADERS = ["Associated Domain", "Method", "Evidence", "Confidence", "Sources Agreeing", "Live"]


def _row(finding: AggregatedFinding) -> list:
    return [
        finding.associated_domain,
        finding.method,
        finding.evidence,
        finding.confidence,
        finding.sources_agreeing,
        "Yes" if finding.live else "No",
    ]


def export_csv(findings: list[AggregatedFinding], path: str | Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(_HEADERS)
        for finding in findings:
            writer.writerow(_row(finding))


def export_xlsx(findings: list[AggregatedFinding], path: str | Path) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill

    wb = Workbook()

    ws = wb.active
    ws.title = "Findings"
    ws.append(_HEADERS)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    high_fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
    for finding in findings:
        ws.append(_row(finding))
        if finding.confidence == "high":
            for cell in ws[ws.max_row]:
                cell.fill = high_fill

    for column_cells in ws.columns:
        length = max(len(str(cell.value)) for cell in column_cells)
        ws.column_dimensions[column_cells[0].column_letter].width = min(length + 2, 80)

    _write_summary_sheet(wb, findings)
    wb.save(path)


def _write_summary_sheet(wb, findings: list[AggregatedFinding]) -> None:
    from openpyxl.styles import Font

    summary = wb.create_sheet("Summary")

    summary.append(["By Confidence"])
    summary["A1"].font = Font(bold=True)
    confidence_counts = Counter(f.confidence for f in findings)
    for tier in ("high", "medium", "low"):
        summary.append([tier, confidence_counts.get(tier, 0)])

    summary.append([])
    row = summary.max_row + 1
    summary.append(["By Method"])
    summary.cell(row=row, column=1).font = Font(bold=True)
    method_counts = Counter()
    for finding in findings:
        for method in finding.method.split("+"):
            method_counts[method] += 1
    for method, count in sorted(method_counts.items(), key=lambda kv: -kv[1]):
        summary.append([method, count])

    summary.append([])
    row = summary.max_row + 1
    summary.append(["By Live status"])
    summary.cell(row=row, column=1).font = Font(bold=True)
    live_counts = Counter("Yes" if f.live else "No" for f in findings)
    for status in ("Yes", "No"):
        summary.append([status, live_counts.get(status, 0)])

    for column_cells in summary.columns:
        length = max(len(str(cell.value)) for cell in column_cells)
        summary.column_dimensions[column_cells[0].column_letter].width = min(length + 2, 40)
