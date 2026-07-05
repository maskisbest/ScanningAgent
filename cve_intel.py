"""
Offline CVE reference lookup and compliance-category mapping.

Design constraints (course design scope, keeps the "no exploitation" boundary
in README.md intact):
- Purely local, hand-curated tables. No network calls, no active CVE database,
  no version-guessing exploitation attempts.
- Only includes CVE IDs the author is confident are accurate and well
  documented; entries tied to a service class rather than a fingerprinted
  version are phrased as "if unpatched" references, not a claim that the
  scanned target is actually vulnerable.
- Compliance tags reuse the scanner's existing CheckRule.category taxonomy
  (17 categories) rather than hand-mapping all 60 rules individually, so the
  mapping stays a single source of truth.
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class CveRef:
    cve_id: str
    severity: str
    summary: str


def _parse_version(text: str) -> Optional[Tuple[int, int, int]]:
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not match:
        return None
    major, minor, patch = match.groups()
    return (int(major), int(minor), int(patch) if patch else 0)


# product -> ordered list of (max_version_inclusive, min_version_inclusive, refs)
# max/min are inclusive bounds; None means unbounded on that side.
_VERSION_CVE_TABLE: Dict[str, List[Tuple[Optional[Tuple[int, int, int]], Optional[Tuple[int, int, int]], List[CveRef]]]] = {
    "openssh": [
        (
            (7, 2, 999),
            None,
            [CveRef("CVE-2016-6210", "中危", "认证阶段用户名可通过响应时间差异被枚举")],
        ),
        (
            (7, 7, 999),
            (7, 3, 0),
            [CveRef("CVE-2018-15473", "中危", "构造特定报文可枚举系统有效用户名")],
        ),
    ],
    "apache": [
        (
            (2, 4, 25),
            (2, 4, 0),
            [CveRef("CVE-2017-7679", "中危", "mod_mime 处理畸形请求导致缓冲区越界读取")],
        ),
        (
            (2, 4, 27),
            (2, 4, 0),
            [CveRef("CVE-2017-9798", "中危", "Optionsbleed：OPTIONS 方法可导致进程内存信息泄露")],
        ),
    ],
    "nginx": [
        (
            (1, 13, 2),
            None,
            [CveRef("CVE-2017-7529", "高危", "range filter 整数溢出，可致敏感信息泄露或拒绝服务")],
        ),
    ],
    "iis": [
        (
            (6, 0, 999),
            (6, 0, 0),
            [CveRef("CVE-2017-7269", "高危", "IIS 6.0 WebDAV ScStoragePathFromUrl 缓冲区溢出，可致远程代码执行")],
        ),
    ],
}

# rule_id -> CVEs associated with this class of exposure (not version-fingerprinted,
# phrased as a conditional reference rather than a confirmed finding).
_RULE_CVE_TABLE: Dict[str, List[CveRef]] = {
    "PORT_SMB_EXPOSED": [
        CveRef("CVE-2017-0144", "高危", "EternalBlue：若为未修补的 SMBv1，可致远程代码执行（WannaCry 曾借此传播）"),
    ],
    "PORT_RDP_EXPOSED": [
        CveRef("CVE-2019-0708", "高危", "BlueKeep：若为未修补的旧版本 RDP 服务，无需认证即可远程代码执行"),
    ],
    "PORT_REDIS_EXPOSED": [
        CveRef("CVE-2022-0543", "高危", "若为 Debian/Ubuntu 系发行版打包的 Redis，存在 Lua 沙箱逃逸导致远程代码执行"),
    ],
    "PORT_ELASTIC_EXPOSED": [
        CveRef("CVE-2015-1427", "高危", "较旧版本 Elasticsearch 的 Groovy 脚本引擎沙箱绕过可致远程代码执行"),
    ],
}

# BANNER_* rule_id -> product key used for version-gated lookups above.
_BANNER_PRODUCT_MAP = {
    "BANNER_OLD_APACHE": "apache",
    "BANNER_OLD_NGINX": "nginx",
    "BANNER_OLD_OPENSSH": "openssh",
    "BANNER_IIS": "iis",
}


def cves_for_finding(rule_id: str, evidence: str) -> List[CveRef]:
    """Look up known CVEs for a finding, by rule (service class) or by parsed banner version."""
    refs = list(_RULE_CVE_TABLE.get(rule_id, ()))
    product = _BANNER_PRODUCT_MAP.get(rule_id)
    if product:
        version = _parse_version(evidence)
        if version:
            for max_v, min_v, table_refs in _VERSION_CVE_TABLE[product]:
                if max_v is not None and version > max_v:
                    continue
                if min_v is not None and version < min_v:
                    continue
                refs.extend(table_refs)
    return refs


# ---------------------------------------------------------------------------
# Compliance mapping: reuse CheckRule.category (see scanner.RULES) as the key,
# so every rule inherits a tag without hand-mapping 60 individual entries.
# ---------------------------------------------------------------------------

# (OWASP Top 10:2021 code + name, GB/T 22239-2019 等保2.0 technical control family)
_CATEGORY_COMPLIANCE_MAP: Dict[str, Tuple[str, str]] = {
    "服务暴露": ("A05:安全配置错误", "安全区域边界"),
    "远程管理": ("A05:安全配置错误", "安全区域边界"),
    "数据库暴露": ("A05:安全配置错误", "安全区域边界"),
    "缓存暴露": ("A05:安全配置错误", "安全区域边界"),
    "容器安全": ("A05:安全配置错误", "安全区域边界"),
    "管理后台": ("A01:失效的访问控制", "安全计算环境"),
    "信息泄露": ("A05:安全配置错误", "安全计算环境"),
    "组件版本": ("A06:自带缺陷的组件", "安全计算环境"),
    "传输安全": ("A02:加密机制失效", "安全通信网络"),
    "HTTP 安全头": ("A05:安全配置错误", "安全计算环境"),
    "会话安全": ("A05:安全配置错误", "安全计算环境"),
    "Web 配置": ("A05:安全配置错误", "安全计算环境"),
    "资产识别": ("A07:身份识别和身份验证错误", "安全计算环境"),
    "敏感信息": ("A05:安全配置错误", "安全计算环境"),
    "接口暴露": ("A05:安全配置错误", "安全计算环境"),
    "认证配置": ("A07:身份识别和身份验证错误", "安全计算环境"),
    "TLS 证书": ("A02:加密机制失效", "安全通信网络"),
}


def compliance_for_category(category: str) -> Tuple[str, str]:
    """Return (owasp_tag, dengbao_tag) for a rule's existing Chinese category.

    Course-design level simplification: rules are tagged by their existing
    category rather than individually, so a category with mixed nuance (e.g.
    "资产识别" covering both login-page discovery and sitemap disclosure)
    gets one best-fit tag instead of a precise per-rule one.
    """
    if category not in _CATEGORY_COMPLIANCE_MAP:
        warnings.warn(
            f"cve_intel: 规则分类 {category!r} 没有对应的合规映射，"
            "已回退到默认标签；新增规则分类时请同步更新 _CATEGORY_COMPLIANCE_MAP。",
            stacklevel=2,
        )
    return _CATEGORY_COMPLIANCE_MAP.get(category, ("A05:安全配置错误", "安全计算环境"))
