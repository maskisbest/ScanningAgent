# 网络漏洞扫描课程设计系统

## 项目信息

- 课程：计算机网络课程设计
- 题目：漏洞扫描程序设计与实现
- 开发人员：请在 `app.py` 的 `AUTHOR_INFO` 中填写姓名、学号、班级、指导老师
- 要求截图：根目录 `要求1.png` 至 `要求4.png` 保存了课程任务要求与参考资料截图
- 代码说明：主要源码位于 Python、HTML、CSS、JavaScript 文件中，页面与导出报告会读取 `AUTHOR_INFO` 中的课程信息
- 说明：本系统仅用于课程设计、授权资产巡检和教学演示，不包含漏洞利用、口令爆破、绕过认证等攻击功能。

## 功能对应要求

- 支持对指定主机和 IP 范围扫描：单 IP、域名、CIDR、起止 IP、逗号分隔混合输入。
- 支持设置扫描目标 IP 地址范围。
- 支持设置并发扫描线程数量。
- 内置 60 条安全检查规则，满足“发现漏洞数量大于 50 个”的课程要求，覆盖 HTTP 安全头、服务暴露、数据库暴露、管理端口、敏感路径、TLS/证书、Banner 信息泄露等。
- 支持扫描结果展示、风险等级划分：高危、中危、低危、信息。
- 支持扫描时长、漏洞数量、目标数量、漏洞类型统计可视化。
- 支持导出 HTML、Text、Word 报告。
- 提供可选“智能分析”接口：未配置 API 时使用本地规则摘要；配置兼容 OpenAI Responses API 的 Key 后可生成更自然的整改建议。

## 创新点

- **离线 CVE 关联匹配**（`cve_intel.py`）：对 banner 中解析出的组件版本（OpenSSH/Apache/nginx/IIS）按版本区间关联已知公开 CVE 编号；对 SMB/RDP/Redis/Elasticsearch 等服务类暴露关联该类服务历史上著名的公开漏洞（如 EternalBlue、BlueKeep），均以“若未修补需关注”的方式呈现，不做在线查询也不做利用尝试。
- **合规映射**（OWASP Top 10:2021 + GB/T 22239-2019 等保 2.0 技术类别）：复用现有 60 条规则的 `category` 分类，为每个风险项自动打上对应的 OWASP 分类和等保技术控制类别标签，报告和仪表盘中新增合规覆盖度统计，方便从"发现了什么漏洞"延伸到"对应哪类安全治理要求"。

## 安装运行

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

浏览器打开：

```text
http://127.0.0.1:5000
```

## 可选智能分析配置

```bash
export OPENAI_API_KEY="你的 API Key"
export OPENAI_MODEL="gpt-4.1-mini"
python app.py
```

如需使用其他兼容 OpenAI Responses API 的网关，可配置：

```bash
export OPENAI_BASE_URL="https://api.openai.com/v1"
```

## 安全边界

请只扫描自己拥有或明确获得授权的资产。系统不会进行：

- 口令爆破
- 漏洞利用
- Web 参数注入测试
- 未授权数据读取
- 破坏性请求

## 公开资料与实现参考标注

代码为本课程设计原创实现，未直接复制公开仓库代码。安全检查项的分类与检测思路参考了下列公开项目/产品的文档或常见能力描述，相关参考仅用于功能设计，不调用其代码：

- Nessus：https://zh-cn.tenable.com/products/nessus
- Burp Suite：https://portswigger.net/burp
- Nikto：https://github.com/sullo/nikto
- w3af：https://github.com/andresriancho/w3af
- SQLMap：https://sourceforge.net/projects/sqlmap/
- OWASP HTTP Headers / Secure Headers 公开建议：https://owasp.org/

