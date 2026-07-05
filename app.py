"""
Network vulnerability scanner course design system.

开发人员信息请在提交前按实际情况修改。代码为课程设计原创实现；
安全检测思路参考 README.md 中列出的公开资料，但未复制第三方项目源码。
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Any, Dict

from flask import Flask, Response, jsonify, redirect, render_template, request, send_file, url_for

import database
from assistant_agent import ai_analysis
from reports import build_docx_report, build_html_report, build_text_report
from scanner import available_rule_count, parse_ports, parse_targets, run_scan, utc_now


AUTHOR_INFO: Dict[str, str] = {
    "student_name": "请填写姓名",
    "student_id": "请填写学号",
    "class_name": "请填写班级",
    "teacher": "请填写指导老师",
    "course": "计算机网络课程设计",
}


app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False


def finish_scan(scan_id: int, target_input: str, ports: str, threads: int) -> None:
    try:
        result = run_scan(target_input, ports, threads)
        now = utc_now()
        database.insert_services(scan_id, result["services"], now)
        database.insert_findings(scan_id, result["findings"], now)
        database.update_scan(
            scan_id,
            status="finished",
            finished_at=now,
            duration_seconds=result["duration_seconds"],
            target_count=len(result["targets"]),
            open_port_count=len(result["services"]),
            finding_count=len(result["findings"]),
        )
    except Exception as exc:
        database.update_scan(scan_id, status="failed", finished_at=utc_now(), error=str(exc))


@app.route("/")
def index() -> str:
    scans = database.list_scans()
    return render_template(
        "index.html",
        scans=scans,
        default_ports=",".join(str(port) for port in parse_ports("")),
        rule_count=available_rule_count(),
        author=AUTHOR_INFO,
    )


def render_error(message: str) -> Response:
    return Response(render_template("error.html", message=message, author=AUTHOR_INFO), status=400)


@app.post("/scan")
def create_scan() -> Response:
    target_input = request.form.get("targets", "").strip()
    ports = request.form.get("ports", "").strip()
    threads = int(request.form.get("threads", "32") or 32)
    if not target_input:
        return render_error("扫描目标不能为空")
    try:
        targets = parse_targets(target_input)
        parsed_ports = parse_ports(ports)
    except Exception as exc:
        return render_error(f"输入参数错误：{exc}")
    if not parsed_ports:
        return render_error("端口列表不能为空")
    ports_text = ",".join(str(port) for port in parsed_ports)
    scan_id = database.create_scan(target_input, ports_text, threads, utc_now())
    database.update_scan(scan_id, target_count=len(targets))
    worker = threading.Thread(target=finish_scan, args=(scan_id, target_input, ports_text, threads), daemon=True)
    worker.start()
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.get("/scan/<int:scan_id>")
def scan_detail(scan_id: int) -> str:
    summary = database.scan_summary(scan_id)
    if not summary:
        return render_template("not_found.html", scan_id=scan_id), 404
    return render_template(
        "scan.html",
        summary=summary,
        author=AUTHOR_INFO,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@app.get("/api/scan/<int:scan_id>")
def scan_api(scan_id: int) -> Response:
    summary = database.scan_summary(scan_id)
    if not summary:
        return jsonify({"error": "scan not found"}), 404
    return jsonify(summary)


@app.post("/api/scan/<int:scan_id>/assistant")
def assistant_api(scan_id: int) -> Response:
    summary = database.scan_summary(scan_id)
    if not summary:
        return jsonify({"error": "scan not found"}), 404
    return jsonify({"analysis": ai_analysis(summary)})


@app.get("/report/<int:scan_id>/<fmt>")
def report(scan_id: int, fmt: str) -> Response:
    summary = database.scan_summary(scan_id)
    if not summary:
        return Response("scan not found", status=404)
    if fmt == "txt":
        content = build_text_report(summary, AUTHOR_INFO)
        return Response(
            content,
            headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.txt"},
            mimetype="text/plain; charset=utf-8",
        )
    if fmt == "html":
        content = build_html_report(summary, AUTHOR_INFO)
        return Response(
            content,
            headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.html"},
            mimetype="text/html; charset=utf-8",
        )
    if fmt == "docx":
        output = build_docx_report(summary, AUTHOR_INFO)
        return send_file(
            output,
            as_attachment=True,
            download_name=f"scan-{scan_id}.docx",
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    return Response("unsupported report format", status=400)


if __name__ == "__main__":
    database.init_db()
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
