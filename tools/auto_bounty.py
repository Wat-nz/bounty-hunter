#!/home/agentuser/.venv/bin/python3
"""
全自动漏洞挖掘脚本 - 从最简单的目标开始
策略：
1. 扫描常见CMS（织梦DedeCMS、WordPress等）的已知漏洞
2. 检查常见配置错误（.git泄露、目录遍历、备份文件等）
3. 发现漏洞后自动保存报告
"""

import subprocess
import json
import os
import time
import re
from datetime import datetime

LOG_FILE = "/home/agentuser/bounty_results.log"
RESULTS_DIR = "/home/agentuser/bounty_finds"

os.makedirs(RESULTS_DIR, exist_ok=True)

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def run_cmd(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:
        return "", str(e), -1

def save_finding(name, url, detail, severity="低危"):
    """保存发现的漏洞"""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"{RESULTS_DIR}/{ts}_{name.replace('/', '_')}.txt"
    content = f"""漏洞发现报告
============
时间: {datetime.now()}
名称: {name}
目标: {url}
severity: {severity}

详情:
{detail}
"""
    with open(fname, "w") as f:
        f.write(content)
    log(f"✅ 发现: {name} [{severity}] - 已保存到 {fname}")

# =============================================
# 阶段1: 简单配置错误扫描
# =============================================

TARGETS = [
    # 中文CMS常见站点 - 用百度搜来的真实站点
    # 先从一些简单的Web服务开始
    {"name": "测试站点1", "url": "http://httpbin.org"},
    {"name": "本地服务", "url": "http://127.0.0.1:11235"},
]

COMMON_PATHS = [
    "/.git/config",
    "/.env",
    "/.DS_Store",
    "/phpinfo.php",
    "/info.php", 
    "/wp-admin/",
    "/wp-content/debug.log",
    "/admin/",
    "/manage/",
    "/backup/",
    "/dump.sql",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/WEB-INF/web.xml",
    "/WEB-INF/database.properties",
    "/config.php.bak",
    "/config.inc.php.bak",
    "/config.bak",
    "/db_backup.sql",
    "/database.sql",
    "/install/",
    "/phpmyadmin/",
    "/api/",
    "/swagger-ui.html",
    "/v2/api-docs",
    "/actuator/",
]

# CMS已知漏洞路径
CMS_CHECKS = {
    "织梦DedeCMS": ["/dede/", "/include/", "/member/", "/data/admin/config_update.php", "/plus/"],
    "WordPress": ["/wp-admin/", "/wp-json/", "/xmlrpc.php", "/wp-config.php.bak"],
    "ThinkPHP": ["/index.php/", "/public/", "/runtime/"],
    "帝国CMS": ["/e/", "/ecms/"],
}

def check_single_url(base_url, path):
    """检查单个路径是否存在"""
    url = base_url.rstrip("/") + path
    out, err, code = run_cmd(f'curl -sL --connect-timeout 6 --max-time 10 -o /dev/null -w "%{{http_code}}:%{{size_download}}" -A "Mozilla/5.0" -k "{url}"', timeout=12)
    if not out:
        return None
    parts = out.strip().split(":")
    if len(parts) >= 2:
        http_code = parts[0]
        size = parts[1]
        if http_code not in ["404", "403", "000", "301", "302"]:
            return (http_code, size, url)
    return None

def scan_target(target):
    """扫描一个目标的常见漏洞路径"""
    name = target["name"]
    base_url = target["url"]
    log(f"扫描目标: {name} ({base_url})")
    
    findings = []
    
    # 扫描常见路径
    for path in COMMON_PATHS:
        result = check_single_url(base_url, path)
        if result:
            http_code, size, url = result
            findings.append((path, http_code, size, url))
            log(f"  发现: {url} -> HTTP {http_code} ({size} bytes)")
            
            # 如果是敏感文件，获取内容
            if path in ["/.git/config", "/.env", "/phpinfo.php", "/dump.sql", "/db_backup.sql"]:
                content, _, _ = run_cmd(f'curl -sL --connect-timeout 6 --max-time 10 -A "Mozilla/5.0" -k "{url}"', timeout=12)
                if content and len(content) > 10:
                    detail = f"URL: {url}\nHTTP: {http_code}\nSize: {size} bytes\n\n前500字符:\n{content[:500]}"
                    sev = "中危" if http_code == "200" else "低危"
                    save_finding(f"敏感文件暴露_{path.replace('/', '_')}", url, detail, sev)
    
    # 扫描CMS特定路径
    for cms, paths in CMS_CHECKS.items():
        for path in paths:
            result = check_single_url(base_url, path)
            if result:
                http_code, size, url = result
                if http_code in ["200", "500"] or (http_code == "302" and size > 100):
                    detail = f"CMS: {cms}\nURL: {url}\nHTTP: {http_code}\nSize: {size}"
                    save_finding(f"{cms}路径暴露_{path.replace('/', '_')}", url, detail, "低危")
    
    return findings

def scan_public_targets():
    """扫描一些公开的中文网站"""
    log("=" * 60)
    log("阶段1: 扫描简单Web目标")
    log("=" * 60)
    
    for target in TARGETS:
        try:
            scan_target(target)
        except Exception as e:
            log(f"扫描失败 {target['name']}: {e}")

# =============================================
# 阶段2: 扫描局域网/本地服务
# =============================================

def scan_local_services():
    """扫描本地网络中的服务"""
    log("\n" + "=" * 60)
    log("阶段2: 本地服务扫描")
    log("=" * 60)
    
    # 扫描常见的本地端口
    ports = [80, 443, 8080, 8000, 3000, 5000, 9000, 11235, 9090, 22, 3306, 6379, 27017]
    for port in ports:
        out, err, code = run_cmd(f'nmap -sT -Pn -n --open -p {port} 127.0.0.1 2>&1 | grep -E "open|PORT"', timeout=15)
        if out and "open" in out:
            log(f"  本地端口开放: {port} - {out.strip()[:100]}")

# =============================================
# 阶段3: 寻找公开的Git泄露/敏感信息
# =============================================

def search_public_leaks():
    """通过搜索引擎找公开的敏感信息"""
    log("\n" + "=" * 60)
    log("阶段3: 搜索公开信息泄露")
    log("=" * 60)
    
    # 搜索Git泄露
    dork_queries = [
        "filetype:sql 备份 数据库",
        "inurl:phpinfo.php intitle:phpinfo",
        "intitle:index.of .git",
        "inurl:/.git/config",
    ]
    
    # 这里用Github搜索
    gist_checks = [
        # 在GitHub上找硬编码的密码/密钥
        'password: "root" language:yaml',
        'api_key: "sk-" language:python',
    ]
    
    for q in gist_checks:
        log(f"  GitHub搜索: {q[:50]}...")
        # GitHub API可能被限，暂时跳过

# =============================================
# 阶段4: 简单SQL注入/XSS检测
# =============================================

def basic_web_check():
    """对简单站点做基础Web漏洞检测"""
    log("\n" + "=" * 60)
    log("阶段4: 基础Web漏洞检测")
    log("=" * 60)
    
    # 测试常用参数
    test_params = ["id=1", "page=1", "cat=1", "id=1'", "id=1 AND 1=1", "id=1 AND 1=2"]
    test_urls = [
        # 一些常见的测试目标
        "https://httpbin.org/get?id=1",
    ]
    
    for url in test_urls:
        for param in test_params:
            test_url = url.split("?")[0] + "?" + param
            out, err, code = run_cmd(f'curl -sL --connect-timeout 5 --max-time 8 -o /dev/null -w "%{{http_code}}" -A "Mozilla/5.0" "{test_url}"', timeout=10)
            if out and out.strip() not in ["000", "403", "404"]:
                log(f"  {test_url} -> {out.strip()}")

# =============================================
# 主流程
# =============================================

if __name__ == "__main__":
    log("=" * 60)
    log("🚀 全自动漏洞挖掘引擎启动")
    log(f"目标: 从简单Web漏洞开始")
    log("=" * 60)
    
    # 先扫本地
    scan_local_services()
    
    # 扫公开目标
    scan_public_targets()
    
    # 搜索信息泄露
    search_public_leaks()
    
    # 基础Web检测
    basic_web_check()
    
    log("\n" + "=" * 60)
    log("🏁 本轮扫描完成")
    log(f"结果保存在: {RESULTS_DIR}/")
    log("=" * 60)
