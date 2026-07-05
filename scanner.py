"""
Network vulnerability scanner core.

This file is original coursework code. It borrows only high-level detection
ideas from public vulnerability scanners listed in README.md. The scanner uses
non-destructive checks: TCP connect, HTTP header inspection, safe well-known
path probes, TLS certificate inspection and banner analysis.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urljoin

import requests

import cve_intel


DEFAULT_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    2049,
    2375,
    2376,
    3306,
    3389,
    5432,
    5601,
    5900,
    5984,
    6379,
    8000,
    8080,
    8443,
    9000,
    9200,
    9300,
    11211,
    27017,
]

HTTP_PORTS = {80, 443, 8000, 8080, 8081, 8443, 9000, 9200, 5601, 5984}

SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "SQL Server",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker API",
    2376: "Docker TLS API",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    8000: "HTTP Alt",
    8080: "HTTP Proxy/Admin",
    8443: "HTTPS Alt",
    9000: "HTTP Admin",
    9200: "Elasticsearch",
    9300: "Elasticsearch Transport",
    11211: "Memcached",
    27017: "MongoDB",
}

SAFE_PATHS = [
    "/",
    "/admin/",
    "/login",
    "/manager/html",
    "/phpinfo.php",
    "/server-status",
    "/.git/HEAD",
    "/.env",
    "/backup.zip",
    "/backup.tar.gz",
    "/swagger-ui/",
    "/swagger.json",
    "/api-docs",
    "/actuator/health",
    "/actuator/env",
    "/robots.txt",
    "/sitemap.xml",
]


@dataclass(frozen=True)
class CheckRule:
    rule_id: str
    title: str
    severity: str
    category: str
    recommendation: str
    source: str = "本课程设计原创规则，检测思路参考 OWASP/常见漏洞扫描器能力描述"


RULES: Dict[str, CheckRule] = {
    "PORT_FTP_EXPOSED": CheckRule("PORT_FTP_EXPOSED", "FTP 服务暴露", "中危", "服务暴露", "如非必要关闭 FTP，改用 SFTP/FTPS，并限制来源地址。"),
    "PORT_TELNET_EXPOSED": CheckRule("PORT_TELNET_EXPOSED", "Telnet 明文远程登录暴露", "高危", "服务暴露", "关闭 Telnet，使用 SSH，并启用强认证策略。"),
    "PORT_SMTP_EXPOSED": CheckRule("PORT_SMTP_EXPOSED", "SMTP 服务暴露", "低危", "服务暴露", "确认邮件服务是否必要，限制中继和来源地址。"),
    "PORT_POP3_EXPOSED": CheckRule("PORT_POP3_EXPOSED", "POP3 邮件服务暴露", "低危", "服务暴露", "优先使用加密邮件协议，关闭明文 POP3。"),
    "PORT_IMAP_EXPOSED": CheckRule("PORT_IMAP_EXPOSED", "IMAP 邮件服务暴露", "低危", "服务暴露", "优先使用加密 IMAPS，并限制访问来源。"),
    "PORT_SMB_EXPOSED": CheckRule("PORT_SMB_EXPOSED", "SMB 文件共享端口暴露", "高危", "服务暴露", "禁止公网暴露 SMB，限制内网网段并开启审计。"),
    "PORT_RPC_EXPOSED": CheckRule("PORT_RPC_EXPOSED", "MS RPC 端口暴露", "中危", "服务暴露", "限制 RPC 访问来源，开启主机防火墙。"),
    "PORT_NETBIOS_EXPOSED": CheckRule("PORT_NETBIOS_EXPOSED", "NetBIOS 端口暴露", "中危", "服务暴露", "关闭不必要的 NetBIOS 服务。"),
    "PORT_RDP_EXPOSED": CheckRule("PORT_RDP_EXPOSED", "RDP 远程桌面暴露", "高危", "远程管理", "不要将 RDP 直接暴露到公网，使用 VPN、堡垒机和 MFA。"),
    "PORT_VNC_EXPOSED": CheckRule("PORT_VNC_EXPOSED", "VNC 远程桌面暴露", "高危", "远程管理", "关闭公网 VNC，强制使用 VPN 和强密码。"),
    "PORT_MYSQL_EXPOSED": CheckRule("PORT_MYSQL_EXPOSED", "MySQL 数据库端口暴露", "高危", "数据库暴露", "数据库禁止公网访问，绑定内网地址并配置白名单。"),
    "PORT_POSTGRES_EXPOSED": CheckRule("PORT_POSTGRES_EXPOSED", "PostgreSQL 数据库端口暴露", "高危", "数据库暴露", "数据库禁止公网访问，配置 pg_hba 白名单。"),
    "PORT_SQLSERVER_EXPOSED": CheckRule("PORT_SQLSERVER_EXPOSED", "SQL Server 数据库端口暴露", "高危", "数据库暴露", "限制 SQL Server 来源地址并启用强认证。"),
    "PORT_ORACLE_EXPOSED": CheckRule("PORT_ORACLE_EXPOSED", "Oracle 数据库端口暴露", "高危", "数据库暴露", "限制 Oracle Listener 访问来源并更新补丁。"),
    "PORT_REDIS_EXPOSED": CheckRule("PORT_REDIS_EXPOSED", "Redis 服务端口暴露", "高危", "数据库暴露", "Redis 仅绑定本机或内网，开启 requirepass/ACL 和防火墙。"),
    "PORT_MONGO_EXPOSED": CheckRule("PORT_MONGO_EXPOSED", "MongoDB 服务端口暴露", "高危", "数据库暴露", "禁止公网访问 MongoDB，开启认证和 TLS。"),
    "PORT_ELASTIC_EXPOSED": CheckRule("PORT_ELASTIC_EXPOSED", "Elasticsearch 服务暴露", "高危", "数据库暴露", "限制 Elasticsearch 来源，启用认证与 TLS。"),
    "PORT_MEMCACHED_EXPOSED": CheckRule("PORT_MEMCACHED_EXPOSED", "Memcached 服务暴露", "高危", "缓存暴露", "Memcached 禁止公网访问，绑定内网地址。"),
    "PORT_COUCHDB_EXPOSED": CheckRule("PORT_COUCHDB_EXPOSED", "CouchDB 服务暴露", "高危", "数据库暴露", "限制 CouchDB 来源，开启管理员认证。"),
    "PORT_DOCKER_API_EXPOSED": CheckRule("PORT_DOCKER_API_EXPOSED", "Docker Remote API 暴露", "高危", "容器安全", "关闭未授权 Docker API，启用 TLS 客户端证书认证。"),
    "PORT_KIBANA_EXPOSED": CheckRule("PORT_KIBANA_EXPOSED", "Kibana 管理界面暴露", "中危", "管理后台", "Kibana 应放在内网或 SSO 后方，启用认证。"),
    "PORT_ADMIN_HTTP": CheckRule("PORT_ADMIN_HTTP", "常见 Web 管理端口开放", "中危", "管理后台", "管理端口应限制来源地址并启用身份认证。"),
    "BANNER_VERSION_LEAK": CheckRule("BANNER_VERSION_LEAK", "服务 Banner 泄露版本信息", "低危", "信息泄露", "隐藏或最小化 Server/X-Powered-By 等版本信息。"),
    "BANNER_OLD_APACHE": CheckRule("BANNER_OLD_APACHE", "Apache 版本可能过旧", "中危", "组件版本", "升级 Apache 到受支持版本并关闭版本回显。"),
    "BANNER_OLD_NGINX": CheckRule("BANNER_OLD_NGINX", "Nginx 版本可能过旧", "中危", "组件版本", "升级 Nginx 到受支持版本并关闭 server_tokens。"),
    "BANNER_OLD_OPENSSH": CheckRule("BANNER_OLD_OPENSSH", "OpenSSH 版本可能过旧", "中危", "组件版本", "升级 OpenSSH 并禁用弱算法。"),
    "BANNER_PHP_EXPOSED": CheckRule("BANNER_PHP_EXPOSED", "PHP 版本信息泄露", "低危", "信息泄露", "关闭 expose_php 并升级 PHP。"),
    "BANNER_TOMCAT": CheckRule("BANNER_TOMCAT", "Tomcat 信息泄露", "低危", "信息泄露", "隐藏 Tomcat 版本并保护管理后台。"),
    "BANNER_IIS": CheckRule("BANNER_IIS", "IIS 信息泄露", "低危", "信息泄露", "减少 IIS 版本回显并及时打补丁。"),
    "HTTP_NO_HTTPS": CheckRule("HTTP_NO_HTTPS", "HTTP 明文服务", "中危", "传输安全", "部署 HTTPS 并将 HTTP 重定向到 HTTPS。"),
    "HTTP_MISSING_HSTS": CheckRule("HTTP_MISSING_HSTS", "缺少 HSTS 响应头", "中危", "HTTP 安全头", "添加 Strict-Transport-Security 响应头。"),
    "HTTP_MISSING_CSP": CheckRule("HTTP_MISSING_CSP", "缺少内容安全策略 CSP", "中危", "HTTP 安全头", "添加 Content-Security-Policy 减少 XSS 风险。"),
    "HTTP_MISSING_XFO": CheckRule("HTTP_MISSING_XFO", "缺少 X-Frame-Options", "中危", "HTTP 安全头", "添加 X-Frame-Options 或 frame-ancestors 防点击劫持。"),
    "HTTP_MISSING_XCTO": CheckRule("HTTP_MISSING_XCTO", "缺少 X-Content-Type-Options", "低危", "HTTP 安全头", "添加 X-Content-Type-Options: nosniff。"),
    "HTTP_MISSING_REFPOL": CheckRule("HTTP_MISSING_REFPOL", "缺少 Referrer-Policy", "低危", "HTTP 安全头", "添加合理的 Referrer-Policy。"),
    "HTTP_MISSING_PERMPOL": CheckRule("HTTP_MISSING_PERMPOL", "缺少 Permissions-Policy", "低危", "HTTP 安全头", "添加 Permissions-Policy 限制浏览器能力。"),
    "HTTP_COOKIE_NO_HTTPONLY": CheckRule("HTTP_COOKIE_NO_HTTPONLY", "Cookie 缺少 HttpOnly", "中危", "会话安全", "为敏感 Cookie 设置 HttpOnly。"),
    "HTTP_COOKIE_NO_SECURE": CheckRule("HTTP_COOKIE_NO_SECURE", "Cookie 缺少 Secure", "中危", "会话安全", "HTTPS 站点为 Cookie 设置 Secure。"),
    "HTTP_COOKIE_NO_SAMESITE": CheckRule("HTTP_COOKIE_NO_SAMESITE", "Cookie 缺少 SameSite", "低危", "会话安全", "为 Cookie 设置 SameSite=Lax/Strict。"),
    "HTTP_SERVER_HEADER": CheckRule("HTTP_SERVER_HEADER", "Server 响应头泄露", "低危", "信息泄露", "隐藏 Server 响应头或移除具体版本。"),
    "HTTP_POWERED_BY_HEADER": CheckRule("HTTP_POWERED_BY_HEADER", "X-Powered-By 响应头泄露", "低危", "信息泄露", "移除 X-Powered-By 响应头。"),
    "HTTP_DIRECTORY_LISTING": CheckRule("HTTP_DIRECTORY_LISTING", "目录列表功能开启", "中危", "Web 配置", "关闭目录浏览并检查敏感文件。"),
    "HTTP_DEFAULT_PAGE": CheckRule("HTTP_DEFAULT_PAGE", "默认欢迎页或示例页", "低危", "Web 配置", "删除默认页面和示例应用。"),
    "HTTP_ADMIN_PAGE": CheckRule("HTTP_ADMIN_PAGE", "发现管理后台入口", "中危", "管理后台", "管理后台应限制来源地址、启用 MFA 和强认证。"),
    "HTTP_LOGIN_PAGE": CheckRule("HTTP_LOGIN_PAGE", "发现登录入口", "信息", "资产识别", "确认登录入口是否需要暴露，配置速率限制和 MFA。"),
    "HTTP_PHPINFO": CheckRule("HTTP_PHPINFO", "phpinfo 页面暴露", "高危", "敏感信息", "立即删除 phpinfo.php，避免泄露环境变量和组件信息。"),
    "HTTP_SERVER_STATUS": CheckRule("HTTP_SERVER_STATUS", "服务状态页面暴露", "中危", "敏感信息", "限制 /server-status 仅本机或内网访问。"),
    "HTTP_GIT_EXPOSED": CheckRule("HTTP_GIT_EXPOSED", ".git 目录暴露", "高危", "敏感信息", "禁止访问 .git 目录，检查源码泄露。"),
    "HTTP_ENV_EXPOSED": CheckRule("HTTP_ENV_EXPOSED", ".env 配置文件暴露", "高危", "敏感信息", "立即删除公网 .env 文件并轮换泄露凭据。"),
    "HTTP_BACKUP_EXPOSED": CheckRule("HTTP_BACKUP_EXPOSED", "备份压缩包疑似暴露", "高危", "敏感信息", "删除公网备份文件并检查泄露内容。"),
    "HTTP_SWAGGER_EXPOSED": CheckRule("HTTP_SWAGGER_EXPOSED", "Swagger/API 文档暴露", "中危", "接口暴露", "接口文档应加认证或仅内网访问。"),
    "HTTP_ACTUATOR_EXPOSED": CheckRule("HTTP_ACTUATOR_EXPOSED", "Spring Actuator 端点暴露", "高危", "接口暴露", "关闭敏感 actuator 端点或限制内网访问。"),
    "HTTP_ROBOTS_DISCLOSE": CheckRule("HTTP_ROBOTS_DISCLOSE", "robots.txt 暴露敏感路径线索", "低危", "信息泄露", "避免在 robots.txt 写入敏感管理路径。"),
    "HTTP_SITEMAP_DISCLOSE": CheckRule("HTTP_SITEMAP_DISCLOSE", "sitemap.xml 暴露路径结构", "信息", "资产识别", "确认站点地图中不存在敏感路径。"),
    "HTTP_BASIC_AUTH": CheckRule("HTTP_BASIC_AUTH", "Basic 认证入口", "低危", "认证配置", "Basic 认证必须配合 HTTPS，并优先使用更强认证方式。"),
    "HTTP_WEAK_TLS_REDIRECT": CheckRule("HTTP_WEAK_TLS_REDIRECT", "HTTPS 未强制跳转迹象", "中危", "传输安全", "将 HTTP 301/308 重定向到 HTTPS。"),
    "TLS_CERT_EXPIRED": CheckRule("TLS_CERT_EXPIRED", "TLS 证书已过期", "高危", "TLS 证书", "更新 TLS 证书并配置自动续期。"),
    "TLS_CERT_EXPIRING": CheckRule("TLS_CERT_EXPIRING", "TLS 证书即将过期", "中危", "TLS 证书", "在 30 天内完成证书续期。"),
    "TLS_SELF_SIGNED": CheckRule("TLS_SELF_SIGNED", "疑似自签名证书", "中危", "TLS 证书", "使用受信任 CA 证书。"),
    "TLS_HOSTNAME_MISMATCH": CheckRule("TLS_HOSTNAME_MISMATCH", "TLS 证书主机名不匹配", "中危", "TLS 证书", "为目标域名签发匹配证书。"),
}

PORT_RULES = {
    21: "PORT_FTP_EXPOSED",
    23: "PORT_TELNET_EXPOSED",
    25: "PORT_SMTP_EXPOSED",
    110: "PORT_POP3_EXPOSED",
    143: "PORT_IMAP_EXPOSED",
    135: "PORT_RPC_EXPOSED",
    139: "PORT_NETBIOS_EXPOSED",
    445: "PORT_SMB_EXPOSED",
    1433: "PORT_SQLSERVER_EXPOSED",
    1521: "PORT_ORACLE_EXPOSED",
    2375: "PORT_DOCKER_API_EXPOSED",
    2376: "PORT_DOCKER_API_EXPOSED",
    3306: "PORT_MYSQL_EXPOSED",
    3389: "PORT_RDP_EXPOSED",
    5432: "PORT_POSTGRES_EXPOSED",
    5601: "PORT_KIBANA_EXPOSED",
    5900: "PORT_VNC_EXPOSED",
    5984: "PORT_COUCHDB_EXPOSED",
    6379: "PORT_REDIS_EXPOSED",
    8080: "PORT_ADMIN_HTTP",
    8443: "PORT_ADMIN_HTTP",
    9000: "PORT_ADMIN_HTTP",
    9200: "PORT_ELASTIC_EXPOSED",
    9300: "PORT_ELASTIC_EXPOSED",
    11211: "PORT_MEMCACHED_EXPOSED",
    27017: "PORT_MONGO_EXPOSED",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def parse_targets(raw: str, max_targets: int = 512) -> List[str]:
    targets: List[str] = []
    for chunk in re.split(r"[\s,;]+", raw.strip()):
        if not chunk:
            continue
        if "-" in chunk and "/" not in chunk:
            start, end = chunk.split("-", 1)
            try:
                start_ip = ipaddress.ip_address(start.strip())
                end_ip = ipaddress.ip_address(end.strip())
                if start_ip.version != end_ip.version:
                    raise ValueError("IP version mismatch")
                current = int(start_ip)
                last = int(end_ip)
                if current > last:
                    current, last = last, current
                for value in range(current, last + 1):
                    targets.append(str(ipaddress.ip_address(value)))
            except ValueError:
                targets.append(chunk)
        elif "/" in chunk:
            try:
                network = ipaddress.ip_network(chunk, strict=False)
                for ip in network.hosts():
                    targets.append(str(ip))
                if network.num_addresses <= 2:
                    targets.append(str(network.network_address))
            except ValueError:
                targets.append(chunk)
        else:
            targets.append(chunk)
        if len(targets) > max_targets:
            raise ValueError(f"目标数量超过上限 {max_targets}，请缩小扫描范围")
    seen = set()
    unique = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique.append(target)
    return unique


def parse_ports(raw: str) -> List[int]:
    if not raw.strip():
        return DEFAULT_PORTS
    ports: List[int] = []
    for chunk in re.split(r"[\s,;]+", raw.strip()):
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            for port in range(int(start), int(end) + 1):
                if 1 <= port <= 65535:
                    ports.append(port)
        else:
            port = int(chunk)
            if 1 <= port <= 65535:
                ports.append(port)
    return sorted(set(ports))


def finding(host: str, port: Optional[int], service: str, rule_id: str, evidence: str) -> Dict[str, Any]:
    rule = RULES[rule_id]
    owasp, dengbao = cve_intel.compliance_for_category(rule.category)
    cve_refs = cve_intel.cves_for_finding(rule_id, evidence)
    return {
        "host": host,
        "port": port,
        "service": service,
        "rule_id": rule.rule_id,
        "title": rule.title,
        "severity": rule.severity,
        "category": rule.category,
        "evidence": evidence[:800],
        "recommendation": rule.recommendation,
        "source": rule.source,
        "owasp_category": owasp,
        "dengbao_category": dengbao,
        "cve_refs": [
            {"id": ref.cve_id, "severity": ref.severity, "summary": ref.summary} for ref in cve_refs
        ],
    }


def tcp_probe(host: str, port: int, timeout: float = 1.5) -> Optional[Dict[str, Any]]:
    service = SERVICE_NAMES.get(port, "unknown")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = ""
            try:
                if port in {80, 8080, 8000, 9000, 9200, 5601, 5984}:
                    sock.sendall(b"HEAD / HTTP/1.1\r\nHost: scan.local\r\nConnection: close\r\n\r\n")
                elif port in {443, 8443}:
                    pass
                else:
                    banner = sock.recv(160).decode("utf-8", errors="ignore").strip()
            except (socket.timeout, OSError):
                banner = ""
            return {
                "host": host,
                "port": port,
                "protocol": "tcp",
                "service": service,
                "banner": banner,
                "metadata": {},
            }
    except OSError:
        return None


def request_http(host: str, port: int, path: str = "/", timeout: float = 2.5) -> Optional[Dict[str, Any]]:
    scheme = "https" if port in {443, 8443} else "http"
    base = f"{scheme}://{host}:{port}"
    url = urljoin(base, path)
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
            headers={"User-Agent": "CourseDesignSafeScanner/1.0"},
        )
        text = resp.text[:3000] if resp.text else ""
        return {
            "url": url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": text,
        }
    except requests.RequestException:
        return None


def inspect_tls(host: str, port: int) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=2.5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                subject = str(cert.get("subject", ""))
                issuer = str(cert.get("issuer", ""))
                if subject and issuer and subject == issuer:
                    results.append(finding(host, port, "HTTPS", "TLS_SELF_SIGNED", "证书 subject 与 issuer 相同"))
                if not_after:
                    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days = (expires - datetime.now(timezone.utc)).days
                    if days < 0:
                        results.append(finding(host, port, "HTTPS", "TLS_CERT_EXPIRED", f"证书已过期 {abs(days)} 天"))
                    elif days <= 30:
                        results.append(finding(host, port, "HTTPS", "TLS_CERT_EXPIRING", f"证书剩余 {days} 天过期"))
    except ssl.CertificateError as exc:
        results.append(finding(host, port, "HTTPS", "TLS_HOSTNAME_MISMATCH", str(exc)))
    except ssl.SSLCertVerificationError as exc:
        message = str(exc)
        if "self-signed" in message.lower():
            results.append(finding(host, port, "HTTPS", "TLS_SELF_SIGNED", message))
        else:
            results.append(finding(host, port, "HTTPS", "TLS_HOSTNAME_MISMATCH", message))
    except Exception:
        pass
    return results


def banner_findings(service: Dict[str, Any]) -> List[Dict[str, Any]]:
    host = service["host"]
    port = int(service["port"])
    name = service.get("service", "")
    banner = service.get("banner", "") or ""
    data = f"{name} {banner}"
    results: List[Dict[str, Any]] = []
    if re.search(r"\d+\.\d+", data):
        results.append(finding(host, port, name, "BANNER_VERSION_LEAK", data))
    if re.search(r"Apache/([01]\.|2\.[0123]\.)", data, re.I):
        results.append(finding(host, port, name, "BANNER_OLD_APACHE", data))
    if re.search(r"nginx/([01]\.|1\.(0|1|2|3|4|5|6|7|8|9|10|11|12)\.)", data, re.I):
        results.append(finding(host, port, name, "BANNER_OLD_NGINX", data))
    if re.search(r"OpenSSH_([1-6]\.|7\.[0-6])", data, re.I):
        results.append(finding(host, port, name, "BANNER_OLD_OPENSSH", data))
    if "php/" in data.lower() or "x-powered-by: php" in data.lower():
        results.append(finding(host, port, name, "BANNER_PHP_EXPOSED", data))
    if "tomcat" in data.lower():
        results.append(finding(host, port, name, "BANNER_TOMCAT", data))
    if "microsoft-iis" in data.lower():
        results.append(finding(host, port, name, "BANNER_IIS", data))
    return results


def http_findings(host: str, port: int, root: Dict[str, Any], extra: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    service = "HTTPS" if port in {443, 8443} else "HTTP"
    headers = {key.lower(): value for key, value in root.get("headers", {}).items()}
    body = root.get("body", "")
    status = root.get("status_code")
    results: List[Dict[str, Any]] = []
    if port not in {443, 8443}:
        results.append(finding(host, port, service, "HTTP_NO_HTTPS", f"{root['url']} 返回 HTTP {status}"))
        location = headers.get("location", "")
        if status not in {301, 302, 307, 308} or not location.startswith("https://"):
            results.append(finding(host, port, service, "HTTP_WEAK_TLS_REDIRECT", "HTTP 未跳转到 HTTPS"))
    if port in {443, 8443} and "strict-transport-security" not in headers:
        results.append(finding(host, port, service, "HTTP_MISSING_HSTS", "响应头缺少 Strict-Transport-Security"))
    if "content-security-policy" not in headers:
        results.append(finding(host, port, service, "HTTP_MISSING_CSP", "响应头缺少 Content-Security-Policy"))
    if "x-frame-options" not in headers and "content-security-policy" in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        results.append(finding(host, port, service, "HTTP_MISSING_XFO", "响应头缺少 X-Frame-Options/frame-ancestors"))
    elif "x-frame-options" not in headers:
        results.append(finding(host, port, service, "HTTP_MISSING_XFO", "响应头缺少 X-Frame-Options"))
    if "x-content-type-options" not in headers:
        results.append(finding(host, port, service, "HTTP_MISSING_XCTO", "响应头缺少 X-Content-Type-Options"))
    if "referrer-policy" not in headers:
        results.append(finding(host, port, service, "HTTP_MISSING_REFPOL", "响应头缺少 Referrer-Policy"))
    if "permissions-policy" not in headers:
        results.append(finding(host, port, service, "HTTP_MISSING_PERMPOL", "响应头缺少 Permissions-Policy"))
    if "server" in headers:
        results.append(finding(host, port, service, "HTTP_SERVER_HEADER", headers["server"]))
    if "x-powered-by" in headers:
        results.append(finding(host, port, service, "HTTP_POWERED_BY_HEADER", headers["x-powered-by"]))
    cookie_headers = [value for key, value in headers.items() if key == "set-cookie"]
    for cookie in cookie_headers:
        lower = cookie.lower()
        if "httponly" not in lower:
            results.append(finding(host, port, service, "HTTP_COOKIE_NO_HTTPONLY", cookie))
        if port in {443, 8443} and "secure" not in lower:
            results.append(finding(host, port, service, "HTTP_COOKIE_NO_SECURE", cookie))
        if "samesite" not in lower:
            results.append(finding(host, port, service, "HTTP_COOKIE_NO_SAMESITE", cookie))
    if re.search(r"<title>index of|directory listing for|parent directory", body, re.I):
        results.append(finding(host, port, service, "HTTP_DIRECTORY_LISTING", "根路径出现目录列表特征"))
    if re.search(r"apache2 ubuntu default page|welcome to nginx|iis windows server|tomcat", body, re.I):
        results.append(finding(host, port, service, "HTTP_DEFAULT_PAGE", "根路径出现默认页面特征"))
    if headers.get("www-authenticate", "").lower().startswith("basic"):
        results.append(finding(host, port, service, "HTTP_BASIC_AUTH", headers.get("www-authenticate", "")))
    path_rules = [
        ("/admin/", "HTTP_ADMIN_PAGE", lambda r: r["status_code"] in {200, 301, 302, 401, 403}),
        ("/login", "HTTP_LOGIN_PAGE", lambda r: r["status_code"] in {200, 301, 302, 401}),
        ("/manager/html", "HTTP_ADMIN_PAGE", lambda r: r["status_code"] in {200, 401, 403}),
        ("/phpinfo.php", "HTTP_PHPINFO", lambda r: r["status_code"] == 200 and "php version" in r["body"].lower()),
        ("/server-status", "HTTP_SERVER_STATUS", lambda r: r["status_code"] == 200 and ("server uptime" in r["body"].lower() or "apache server status" in r["body"].lower())),
        ("/.git/HEAD", "HTTP_GIT_EXPOSED", lambda r: r["status_code"] == 200 and "ref:" in r["body"].lower()),
        ("/.env", "HTTP_ENV_EXPOSED", lambda r: r["status_code"] == 200 and ("=" in r["body"] and ("key" in r["body"].lower() or "password" in r["body"].lower() or "secret" in r["body"].lower()))),
        ("/backup.zip", "HTTP_BACKUP_EXPOSED", lambda r: r["status_code"] == 200),
        ("/backup.tar.gz", "HTTP_BACKUP_EXPOSED", lambda r: r["status_code"] == 200),
        ("/swagger-ui/", "HTTP_SWAGGER_EXPOSED", lambda r: r["status_code"] in {200, 301, 302}),
        ("/swagger.json", "HTTP_SWAGGER_EXPOSED", lambda r: r["status_code"] == 200),
        ("/api-docs", "HTTP_SWAGGER_EXPOSED", lambda r: r["status_code"] == 200),
        ("/actuator/health", "HTTP_ACTUATOR_EXPOSED", lambda r: r["status_code"] == 200),
        ("/actuator/env", "HTTP_ACTUATOR_EXPOSED", lambda r: r["status_code"] in {200, 401, 403}),
        ("/robots.txt", "HTTP_ROBOTS_DISCLOSE", lambda r: r["status_code"] == 200 and "disallow:" in r["body"].lower()),
        ("/sitemap.xml", "HTTP_SITEMAP_DISCLOSE", lambda r: r["status_code"] == 200 and "<urlset" in r["body"].lower()),
    ]
    for path, rule_id, predicate in path_rules:
        response = extra.get(path)
        if response and predicate(response):
            results.append(finding(host, port, service, rule_id, f"{response['url']} 返回 HTTP {response['status_code']}"))
    return results


def scan_service(host: str, port: int) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    service = tcp_probe(host, port)
    if not service:
        return None, []
    findings: List[Dict[str, Any]] = []
    rule_id = PORT_RULES.get(port)
    if rule_id:
        findings.append(finding(host, port, service["service"], rule_id, f"TCP/{port} 开放"))
    findings.extend(banner_findings(service))
    http_probe_allowed = port in HTTP_PORTS or service["service"] == "unknown"
    if http_probe_allowed:
        root = request_http(host, port, "/")
        if root:
            if service["service"] == "unknown":
                service["service"] = "HTTP"
            service["banner"] = root.get("headers", {}).get("Server", service.get("banner", ""))
            service["metadata"]["http"] = {
                "status_code": root.get("status_code"),
                "headers": root.get("headers", {}),
            }
            extra = {}
            for path in SAFE_PATHS[1:]:
                response = request_http(host, port, path)
                if response:
                    extra[path] = response
            findings.extend(http_findings(host, port, root, extra))
            findings.extend(banner_findings(service))
    if port in {443, 8443}:
        findings.extend(inspect_tls(host, port))
    return service, dedupe_findings(findings)


def dedupe_findings(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for item in items:
        key = (item["host"], item.get("port"), item["rule_id"], item.get("evidence", "")[:120])
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def run_scan(target_input: str, ports_input: str, threads: int) -> Dict[str, Any]:
    started = time.time()
    targets = parse_targets(target_input)
    ports = parse_ports(ports_input)
    workers = max(1, min(int(threads), 128))
    services: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    tasks = [(target, port) for target in targets for port in ports]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(scan_service, host, port): (host, port) for host, port in tasks}
        for future in concurrent.futures.as_completed(future_map):
            service, found = future.result()
            if service:
                services.append(service)
            findings.extend(found)
    findings = dedupe_findings(findings)
    return {
        "targets": targets,
        "ports": ports,
        "services": sorted(services, key=lambda item: (item["host"], item["port"])),
        "findings": sorted(
            findings,
            key=lambda item: (
                {"高危": 1, "中危": 2, "低危": 3, "信息": 4}.get(item["severity"], 9),
                item["host"],
                item.get("port") or 0,
            ),
        ),
        "duration_seconds": round(time.time() - started, 2),
    }


def available_rule_count() -> int:
    return len(RULES)
