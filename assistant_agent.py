"""
Optional remediation assistant.

Without an API key it returns a deterministic local summary. With OPENAI_API_KEY
it calls a Responses-API-compatible endpoint. The call is clearly isolated so
the coursework can be demonstrated without external services.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Any, Dict

import requests


def local_analysis(summary: Dict[str, Any]) -> str:
    findings = summary.get("findings", [])
    severity = Counter(item["severity"] for item in findings)
    categories = Counter(item["category"] for item in findings)
    top_categories = "、".join(f"{name}{count}项" for name, count in categories.most_common(5)) or "暂无"
    advice = [
        f"本次扫描发现 {len(findings)} 项风险，其中高危 {severity.get('高危', 0)} 项、中危 {severity.get('中危', 0)} 项、低危 {severity.get('低危', 0)} 项。",
        f"主要风险类型集中在：{top_categories}。",
    ]
    if severity.get("高危", 0):
        advice.append("优先处理数据库/远程管理/敏感文件暴露等高危问题，先通过防火墙或安全组收敛访问面，再修复应用配置。")
    if categories.get("HTTP 安全头", 0):
        advice.append("Web 站点需要补齐 HSTS、CSP、X-Frame-Options、X-Content-Type-Options 等安全响应头。")
    if categories.get("服务暴露", 0) or categories.get("数据库暴露", 0):
        advice.append("对外开放端口应逐项确认业务必要性，不必要端口立即关闭，必要端口加入来源白名单。")
    advice.append("建议整改后重新扫描，并将报告作为课程设计演示材料。")
    return "\n".join(advice)


def ai_analysis(summary: Dict[str, Any]) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return local_analysis(summary)
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    findings = summary.get("findings", [])[:80]
    compact = [
        {
            "host": item["host"],
            "port": item.get("port"),
            "severity": item["severity"],
            "title": item["title"],
            "category": item["category"],
            "evidence": item.get("evidence", "")[:200],
            "owasp": item.get("owasp_category"),
            "dengbao": item.get("dengbao_category"),
            "cve": [c["id"] for c in item.get("cve_refs") or []],
        }
        for item in findings
    ]
    prompt = (
        "你是网络安全课程设计系统的防御型整改助手。"
        "请基于扫描结果生成中文摘要、风险优先级和整改步骤，"
        "并在合适的地方引用样本中提供的 OWASP Top 10 / 等保 2.0 分类和 CVE 编号帮助定级。"
        "不要提供漏洞利用步骤、绕过认证或攻击代码。\n\n"
        f"扫描摘要：{summary.get('scan')}\n"
        f"统计：{summary.get('by_severity')}, {summary.get('by_category')}\n"
        f"合规覆盖：OWASP={summary.get('by_owasp')}, 等保2.0={summary.get('by_dengbao')}\n"
        f"漏洞样本：{compact}"
    )
    try:
        resp = requests.post(
            f"{base_url}/responses",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": model,
                "input": prompt,
                "max_output_tokens": 900,
            },
            timeout=90,
        )
        resp.raise_for_status()
        data = resp.json()
        chunks = []
        for item in data.get("output", []):
            for content in item.get("content", []):
                if content.get("type") in {"output_text", "text"}:
                    chunks.append(content.get("text", ""))
        return "\n".join(chunks).strip() or local_analysis(summary)
    except Exception as exc:
        return local_analysis(summary) + f"\n\nAPI 调用失败，已回退本地分析：{exc}"
