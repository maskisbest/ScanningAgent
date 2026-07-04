"""
Report exporters for HTML, plain text and Word formats.

The Word export uses python-docx and creates a standard .docx document. This
module is original coursework code.
"""

from __future__ import annotations

import html
from io import BytesIO
from typing import Any, Dict, List

from docx import Document
from docx.shared import Inches


SEVERITY_ORDER = ["高危", "中危", "低危", "信息"]


def build_text_report(summary: Dict[str, Any], author_info: Dict[str, str]) -> str:
    scan = summary["scan"]
    lines = [
        "网络漏洞扫描课程设计报告",
        "=" * 32,
        f"开发人员：{author_info.get('student_name', '')}",
        f"学号：{author_info.get('student_id', '')}",
        f"班级：{author_info.get('class_name', '')}",
        f"指导老师：{author_info.get('teacher', '')}",
        "",
        f"扫描目标：{scan['target_input']}",
        f"端口范围：{scan['ports']}",
        f"并发线程：{scan['threads']}",
        f"扫描状态：{scan['status']}",
        f"开始时间：{scan['started_at']}",
        f"结束时间：{scan.get('finished_at') or ''}",
        f"扫描时长：{scan.get('duration_seconds') or 0} 秒",
        f"目标数量：{scan.get('target_count') or 0}",
        f"开放端口：{summary['service_count']}",
        f"漏洞/风险数量：{summary['finding_count']}",
        "",
        "风险等级统计：",
    ]
    for severity in SEVERITY_ORDER:
        lines.append(f"- {severity}: {summary['by_severity'].get(severity, 0)}")
    lines.extend(["", "开放服务："])
    for service in summary["services"]:
        lines.append(f"- {service['host']}:{service['port']} {service['service']} {service.get('banner') or ''}".strip())
    lines.extend(["", "漏洞明细："])
    for idx, finding in enumerate(summary["findings"], 1):
        lines.extend(
            [
                f"{idx}. [{finding['severity']}] {finding['title']}",
                f"   目标：{finding['host']}:{finding.get('port') or '-'}",
                f"   类型：{finding['category']} / {finding['rule_id']}",
                f"   证据：{finding.get('evidence') or ''}",
                f"   建议：{finding.get('recommendation') or ''}",
                f"   来源：{finding.get('source') or ''}",
            ]
        )
    return "\n".join(lines)


def build_html_report(summary: Dict[str, Any], author_info: Dict[str, str]) -> str:
    scan = summary["scan"]
    severity_cards = "".join(
        f"<div class='card'><strong>{html.escape(sev)}</strong><span>{summary['by_severity'].get(sev, 0)}</span></div>"
        for sev in SEVERITY_ORDER
    )
    service_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item['host']))}</td>"
        f"<td>{item['port']}</td>"
        f"<td>{html.escape(item['service'])}</td>"
        f"<td>{html.escape(item.get('banner') or '')}</td>"
        "</tr>"
        for item in summary["services"]
    )
    finding_rows = "".join(
        "<tr>"
        f"<td>{html.escape(item['severity'])}</td>"
        f"<td>{html.escape(item['host'])}:{item.get('port') or '-'}</td>"
        f"<td>{html.escape(item['title'])}</td>"
        f"<td>{html.escape(item['category'])}</td>"
        f"<td>{html.escape(item.get('evidence') or '')}</td>"
        f"<td>{html.escape(item.get('recommendation') or '')}</td>"
        "</tr>"
        for item in summary["findings"]
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>网络漏洞扫描报告 #{scan['id']}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #1f2937; }}
    h1, h2 {{ color: #111827; }}
    table {{ width: 100%; border-collapse: collapse; margin: 12px 0 24px; }}
    th, td {{ border: 1px solid #d1d5db; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f3f4f6; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
    .card {{ border: 1px solid #d1d5db; border-radius: 8px; padding: 14px; }}
    .card span {{ display: block; font-size: 28px; margin-top: 8px; }}
  </style>
</head>
<body>
  <h1>网络漏洞扫描课程设计报告</h1>
  <p>开发人员：{html.escape(author_info.get('student_name', ''))}　
     学号：{html.escape(author_info.get('student_id', ''))}　
     班级：{html.escape(author_info.get('class_name', ''))}　
     指导老师：{html.escape(author_info.get('teacher', ''))}</p>
  <h2>扫描概况</h2>
  <p>目标：{html.escape(scan['target_input'])}</p>
  <p>端口：{html.escape(scan['ports'])}；线程：{scan['threads']}；时长：{scan.get('duration_seconds') or 0} 秒；目标数量：{scan.get('target_count') or 0}</p>
  <div class="grid">{severity_cards}</div>
  <h2>开放服务</h2>
  <table><thead><tr><th>主机</th><th>端口</th><th>服务</th><th>Banner</th></tr></thead><tbody>{service_rows}</tbody></table>
  <h2>漏洞明细</h2>
  <table><thead><tr><th>等级</th><th>目标</th><th>名称</th><th>类型</th><th>证据</th><th>建议</th></tr></thead><tbody>{finding_rows}</tbody></table>
</body>
</html>"""


def build_docx_report(summary: Dict[str, Any], author_info: Dict[str, str]) -> BytesIO:
    scan = summary["scan"]
    doc = Document()
    doc.add_heading("网络漏洞扫描课程设计报告", 0)
    doc.add_paragraph(f"开发人员：{author_info.get('student_name', '')}")
    doc.add_paragraph(f"学号：{author_info.get('student_id', '')}")
    doc.add_paragraph(f"班级：{author_info.get('class_name', '')}")
    doc.add_paragraph(f"指导老师：{author_info.get('teacher', '')}")
    doc.add_heading("扫描概况", level=1)
    table = doc.add_table(rows=0, cols=2)
    table.style = "Table Grid"
    overview = [
        ("扫描目标", scan["target_input"]),
        ("端口范围", scan["ports"]),
        ("并发线程", str(scan["threads"])),
        ("扫描状态", scan["status"]),
        ("开始时间", scan["started_at"]),
        ("结束时间", scan.get("finished_at") or ""),
        ("扫描时长", f"{scan.get('duration_seconds') or 0} 秒"),
        ("目标数量", str(scan.get("target_count") or 0)),
        ("开放端口", str(summary["service_count"])),
        ("漏洞/风险数量", str(summary["finding_count"])),
    ]
    for key, value in overview:
        cells = table.add_row().cells
        cells[0].text = key
        cells[1].text = value
    doc.add_heading("风险等级统计", level=1)
    sev_table = doc.add_table(rows=1, cols=2)
    sev_table.style = "Table Grid"
    sev_table.rows[0].cells[0].text = "等级"
    sev_table.rows[0].cells[1].text = "数量"
    for severity in SEVERITY_ORDER:
        cells = sev_table.add_row().cells
        cells[0].text = severity
        cells[1].text = str(summary["by_severity"].get(severity, 0))
    doc.add_heading("开放服务", level=1)
    service_table = doc.add_table(rows=1, cols=4)
    service_table.style = "Table Grid"
    for idx, title in enumerate(["主机", "端口", "服务", "Banner"]):
        service_table.rows[0].cells[idx].text = title
    for service in summary["services"]:
        cells = service_table.add_row().cells
        cells[0].text = service["host"]
        cells[1].text = str(service["port"])
        cells[2].text = service["service"]
        cells[3].text = service.get("banner") or ""
    doc.add_heading("漏洞明细", level=1)
    for idx, item in enumerate(summary["findings"], 1):
        doc.add_heading(f"{idx}. [{item['severity']}] {item['title']}", level=2)
        doc.add_paragraph(f"目标：{item['host']}:{item.get('port') or '-'}")
        doc.add_paragraph(f"类型：{item['category']} / {item['rule_id']}")
        doc.add_paragraph(f"证据：{item.get('evidence') or ''}")
        doc.add_paragraph(f"建议：{item.get('recommendation') or ''}")
        doc.add_paragraph(f"来源：{item.get('source') or ''}")
    section = doc.sections[0]
    section.top_margin = Inches(0.7)
    section.bottom_margin = Inches(0.7)
    section.left_margin = Inches(0.7)
    section.right_margin = Inches(0.7)
    output = BytesIO()
    doc.save(output)
    output.seek(0)
    return output
