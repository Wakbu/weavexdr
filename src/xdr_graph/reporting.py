from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import re
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from xdr_graph.audit import AuditRecord
from xdr_graph.models import IncidentReport


_USER_PATH = re.compile(r"(?i)([A-Z]:\\Users\\)[^\\/]+")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class ExportArtifact:
    path: Path
    media_type: str
    sha256: str


def redact_sensitive(value: Any) -> Any:
    """공유 보고서에서는 사용자 프로필 경로를 유지하되 계정명만 제거한다."""
    if isinstance(value, str):
        return _USER_PATH.sub(r"\1<USER>", value)
    if isinstance(value, dict):
        return {str(key): redact_sensitive(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [redact_sensitive(nested) for nested in value]
    return value


class IncidentReportExporter:
    """사건 보고서와 해시 검증 가능한 증적 묶음을 로컬 폴더에 생성한다."""

    def __init__(self, output_root: str | Path) -> None:
        self.output_root = Path(output_root).resolve()
        self.output_root.mkdir(parents=True, exist_ok=True)

    def export(
        self,
        report: IncidentReport,
        management: dict[str, object],
        format_name: str,
        *,
        audit_records: Iterable[AuditRecord] = (),
        redact: bool = True,
        include_notes: bool = True,
    ) -> ExportArtifact:
        payload = report.model_dump(mode="json")
        management_payload = dict(management) if include_notes else {
            key: value for key, value in management.items() if key not in {"note", "checklist"}
        }
        if redact:
            payload = redact_sensitive(payload)
            management_payload = redact_sensitive(management_payload)
        safe_id = _SAFE_NAME.sub("_", report.incident_id)[:100]
        stem = f"weavexdr-{safe_id}"
        audit_payload = [redact_sensitive(item.model_dump(mode="json")) for item in audit_records]
        writers = {
            "json": lambda path: path.write_text(json.dumps({"report": payload, "management": management_payload}, ensure_ascii=False, indent=2), encoding="utf-8"),
            "csv": lambda path: self._write_csv(path, payload),
            "stix": lambda path: path.write_text(json.dumps(self._stix_bundle(payload), ensure_ascii=False, indent=2), encoding="utf-8"),
            "html": lambda path: path.write_text(self._html(payload, management_payload), encoding="utf-8"),
            "pdf": lambda path: self._pdf(path, payload, management_payload),
        }
        if format_name == "evidence":
            path = self.output_root / f"{stem}-evidence.zip"
            self._evidence_zip(path, payload, management_payload, audit_payload)
            return self._artifact(path, "application/zip")
        if format_name not in writers:
            raise ValueError("unsupported report format")
        suffix = "json" if format_name == "stix" else format_name
        path = self.output_root / f"{stem}.{suffix}"
        writers[format_name](path)
        media_types = {"json": "application/json", "csv": "text/csv", "stix": "application/stix+json", "html": "text/html", "pdf": "application/pdf"}
        return self._artifact(path, media_types[format_name])

    @staticmethod
    def _write_csv(path: Path, payload: dict[str, Any]) -> None:
        with path.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["event_id", "timestamp", "type", "process", "file", "source_ip", "destination_ip"])
            for event in payload.get("source_events", []):
                writer.writerow([event.get("event_id"), event.get("timestamp"), event.get("event_type"), event.get("process_name"), event.get("file_path"), event.get("source_ip"), event.get("destination_ip")])

    @staticmethod
    def _stix_bundle(payload: dict[str, Any]) -> dict[str, Any]:
        incident_id = hashlib.sha256(str(payload["incident_id"]).encode()).hexdigest()
        created = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        objects: list[dict[str, Any]] = [{
            "type": "incident", "spec_version": "2.1", "id": f"incident--{incident_id[:8]}-{incident_id[8:12]}-4{incident_id[13:16]}-a{incident_id[17:20]}-{incident_id[20:32]}",
            "created": created, "modified": created, "name": str(payload["incident_id"]),
            "description": "; ".join(payload.get("evidence", [])),
        }]
        return {"type": "bundle", "id": f"bundle--{incident_id[32:40]}-{incident_id[40:44]}-4{incident_id[45:48]}-a{incident_id[49:52]}-{incident_id[52:64]}", "objects": objects}

    @staticmethod
    def _html(payload: dict[str, Any], management: dict[str, object]) -> str:
        findings = "".join(f"<li>{html.escape(str(item.get('reason') or item.get('rule_id')))}</li>" for item in payload.get("findings", [])) or "<li>분석 근거 없음</li>"
        events = "".join(f"<tr><td>{html.escape(str(item.get('timestamp','-')))}</td><td>{html.escape(str(item.get('event_type','-')))}</td><td>{html.escape(str(item.get('process_name') or item.get('file_path') or '-'))}</td></tr>" for item in payload.get("source_events", []))
        return f"""<!doctype html><html lang='ko'><meta charset='utf-8'><title>WeaveXDR 사건 보고서</title><style>body{{font:14px Segoe UI,sans-serif;max-width:980px;margin:40px auto;color:#17202a}}h1{{border-bottom:3px solid #1b7f87;padding-bottom:12px}}.score{{font-size:34px;font-weight:700}}table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #ccd5dc;padding:8px;text-align:left}}small{{color:#64717d}}</style><h1>WeaveXDR 사건 보고서</h1><p><small>{html.escape(str(payload['incident_id']))}</small></p><p class='score'>{payload.get('risk_score',0)} / 100</p><p>판정: {html.escape(str(payload.get('verdict','-')))}</p><h2>탐지 근거</h2><ul>{findings}</ul><h2>사건 활동</h2><table><thead><tr><th>시각</th><th>유형</th><th>대상</th></tr></thead><tbody>{events}</tbody></table><h2>조사 메모</h2><p>{html.escape(str(management.get('note') or '없음'))}</p></html>"""

    @staticmethod
    def _pdf(path: Path, payload: dict[str, Any], management: dict[str, object]) -> None:
        # Windows 기본 맑은 고딕을 PDF에 부분 포함해 다른 PC와 렌더러에서도
        # 한글이 동일하게 보이게 한다. 비 Windows 환경만 CID 글꼴로 대체한다.
        windows_font = Path(r"C:\Windows\Fonts\malgun.ttf")
        font_name = "WeaveXDR-Korean" if windows_font.is_file() else "HYSMyeongJo-Medium"
        try:
            pdfmetrics.getFont(font_name)
        except KeyError:
            if windows_font.is_file():
                pdfmetrics.registerFont(TTFont(font_name, windows_font))
            else:
                pdfmetrics.registerFont(UnicodeCIDFont(font_name))
        styles = getSampleStyleSheet()
        title = ParagraphStyle("KoreanTitle", parent=styles["Title"], fontName=font_name, fontSize=20, leading=27, alignment=TA_CENTER, textColor=colors.HexColor("#163642"))
        heading = ParagraphStyle("KoreanHeading", parent=styles["Heading2"], fontName=font_name, fontSize=13, leading=18, textColor=colors.HexColor("#176b73"))
        body = ParagraphStyle("KoreanBody", parent=styles["BodyText"], fontName=font_name, fontSize=9, leading=14)
        document = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm, title="WeaveXDR 사건 보고서")
        story = [Paragraph("WeaveXDR 사건 보고서", title), Spacer(1, 6*mm), Paragraph(f"사건 ID: {html.escape(str(payload['incident_id']))}", body)]
        summary = Table([["위험 점수", str(payload.get("risk_score", 0)), "판정", str(payload.get("verdict", "-"))]], colWidths=[28*mm, 25*mm, 22*mm, 40*mm])
        summary.setStyle(TableStyle([("FONTNAME",(0,0),(-1,-1),font_name),("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e9f3f4")),("GRID",(0,0),(-1,-1),.5,colors.HexColor("#9db3b8")),("PADDING",(0,0),(-1,-1),7)]))
        story.extend([Spacer(1, 4*mm), summary, Spacer(1, 6*mm), Paragraph("탐지 근거", heading)])
        for finding in payload.get("findings", []) or [{"reason": "분석 근거 없음"}]:
            story.append(Paragraph(f"- {html.escape(str(finding.get('reason') or finding.get('rule_id')))}", body))
        story.extend([Spacer(1, 5*mm), Paragraph("사건 활동", heading)])
        event_rows = [["시각", "유형", "대상"]]
        for event in payload.get("source_events", []):
            event_rows.append([Paragraph(html.escape(str(event.get("timestamp", "-"))), body), Paragraph(html.escape(str(event.get("event_type", "-"))), body), Paragraph(html.escape(str(event.get("process_name") or event.get("file_path") or "-")), body)])
        table = Table(event_rows, repeatRows=1, colWidths=[42*mm, 32*mm, 82*mm])
        table.setStyle(TableStyle([("FONTNAME",(0,0),(-1,-1),font_name),("BACKGROUND",(0,0),(-1,0),colors.HexColor("#163642")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.35,colors.HexColor("#aab7bd")),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),5)]))
        story.extend([table, Spacer(1, 5*mm), Paragraph("조사 메모", heading), Paragraph(html.escape(str(management.get("note") or "없음")), body)])
        document.build(story, onFirstPage=IncidentReportExporter._page_footer, onLaterPages=IncidentReportExporter._page_footer)

    @staticmethod
    def _page_footer(canvas, document) -> None:
        canvas.saveState(); canvas.setFont("Helvetica", 8); canvas.setFillColor(colors.HexColor("#68747b")); canvas.drawRightString(A4[0]-18*mm, 9*mm, f"WeaveXDR · {document.page}"); canvas.restoreState()

    @staticmethod
    def _evidence_zip(path: Path, report: dict[str, Any], management: dict[str, object], audit: list[dict[str, Any]]) -> None:
        files = {
            "incident.json": json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"),
            "management.json": json.dumps(management, ensure_ascii=False, indent=2).encode("utf-8"),
            "audit.json": json.dumps(audit, ensure_ascii=False, indent=2).encode("utf-8"),
        }
        manifest = {"created_at": datetime.now(UTC).isoformat(), "hash_algorithm": "SHA-256", "files": {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}}
        files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in files.items():
                archive.writestr(name, content)

    @staticmethod
    def _artifact(path: Path, media_type: str) -> ExportArtifact:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return ExportArtifact(path=path, media_type=media_type, sha256=digest)


class SecuritySummaryExporter:
    """주·월간 추이와 MITRE 커버리지를 스크립트 없는 읽기 전용 묶음으로 만든다."""

    def __init__(self, output_root: str | Path) -> None:
        self.output_root = Path(output_root).resolve()
        self.output_root.mkdir(parents=True, exist_ok=True)

    def export(self, reports: Iterable[IncidentReport], period: str, *, now: datetime | None = None) -> ExportArtifact:
        if period not in {"weekly", "monthly"}:
            raise ValueError("summary period must be weekly or monthly")
        current = (now or datetime.now(UTC)).astimezone(UTC)
        days = 7 if period == "weekly" else 30
        cutoff = current.timestamp() - days * 86400
        selected = [report for report in reports if any(event.timestamp.timestamp() >= cutoff for event in report.source_events)]
        verdicts = {name: sum(report.verdict == name for report in selected) for name in ("suspicious", "needs_review", "benign")}
        mitre: dict[str, int] = {}
        daily: dict[str, int] = {}
        for report in selected:
            for event in report.source_events:
                if event.timestamp.timestamp() >= cutoff:
                    key = event.timestamp.astimezone(UTC).date().isoformat(); daily[key] = daily.get(key, 0) + 1
            for finding in report.findings:
                for reference in finding.references:
                    if reference.framework == "mitre_attack":
                        mitre[reference.external_id] = mitre.get(reference.external_id, 0) + 1
        payload = {"period": period, "window_days": days, "generated_at": current.isoformat(), "incident_count": len(selected), "verdicts": verdicts, "daily_events": dict(sorted(daily.items())), "mitre_coverage": dict(sorted(mitre.items()))}
        title = "주간" if period == "weekly" else "월간"
        rows = "".join(f"<tr><td>{html.escape(key)}</td><td>{value}</td></tr>" for key, value in payload["mitre_coverage"].items()) or "<tr><td colspan='2'>확인된 ATT&CK 기법 없음</td></tr>"
        page = f"""<!doctype html><html lang='ko'><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>WeaveXDR {title} 보안 요약</title><style>body{{font:14px Segoe UI,sans-serif;max-width:920px;margin:40px auto;color:#17202a}}h1{{border-bottom:3px solid #176b73;padding-bottom:12px}}.cards{{display:flex;gap:12px}}.card{{border:1px solid #cad4da;padding:16px;min-width:130px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #cad4da;padding:8px;text-align:left}}</style><h1>WeaveXDR {title} 보안 요약</h1><p>{days}일 기준 · {html.escape(current.isoformat())}</p><div class='cards'><div class='card'>전체 사건<br><b>{len(selected)}</b></div><div class='card'>고위험<br><b>{verdicts['suspicious']}</b></div><div class='card'>검토 필요<br><b>{verdicts['needs_review']}</b></div></div><h2>MITRE ATT&CK 커버리지</h2><table><tr><th>기법</th><th>탐지 횟수</th></tr>{rows}</table></html>"""
        stem = f"weavexdr-{period}-summary-{current.date().isoformat()}"; package = self.output_root / f"{stem}.zip"
        files = {"index.html": page.encode("utf-8"), "summary.json": json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")}
        manifest = {"generated_at": current.isoformat(), "read_only": True, "files": {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}}
        files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
        with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in files.items(): archive.writestr(name, content)
        return IncidentReportExporter._artifact(package, "application/zip")
