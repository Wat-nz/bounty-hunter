#!/home/agentuser/.venv/bin/python3
"""
自动审计PHP CMS项目 - 找高危漏洞
从Gitee拉取多个项目做代码审计
"""

import subprocess
import re
import os
import sys
from datetime import datetime

RESULTS_DIR = "/home/agentuser/bounty_finds"
os.makedirs(RESULTS_DIR, exist_ok=True)

def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except:
        return "", "TIMEOUT", -1

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def save_finding(name, detail, severity):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r'[^\w\-\.]', '_', name)[:30]
    fname = f"{RESULTS_DIR}/{ts}_{safe}.txt"
    with open(fname, "w") as f:
        f.write(f"漏洞: {name}\n等级: {severity}\n时间: {datetime.now()}\n\n{detail}\n")
    log(f"✅ [{severity}] {name}")

# 高危模式检测
VULN_PATTERNS = [
    # SQL注入 - 直接拼接请求参数到SQL
    ("SQL注入(直接拼接GET)", 
     r'\$_(GET|POST|REQUEST)\s*\[\s*["\']([^"\']+)["\']\s*\][^;]{0,100}(?:query|Query|exec|select|insert|update|delete)\s*\(',
     "严重"),
    
    # SQL注入 - 请求参数直接拼接到where
    ("SQL注入(拼接WHERE)", r'where.*?["\']\s*\.\s*\$_(?:GET|POST|REQUEST)', "严重"),
    
    # 命令注入
    ("命令注入",
     r'(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^)]{0,50}\$_(?:GET|POST|REQUEST|SERVER)\s*\[',
     "严重"),
    
    # 命令注入2 - system/exec拼接变量
    ("命令注入(拼接)",
     r'(?:system|exec|shell_exec|passthru)\s*\(\s*["\'].*?["\']\s*\.\s*\$',
     "高危"),
    
    # 文件包含
    ("文件包含(LFI)",
     r'(?:include|require|include_once|require_once)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)\[|["\']\s*\.\s*\$)',
     "高危"),
    
    # 文件写入
    ("文件写入",
     r'(?:file_put_contents|fwrite|fputs|file_put_contents)\s*\([^)]{0,50}\$_(?:GET|POST|REQUEST)',
     "严重"),
    
    # 反序列化
    ("反序列化",
     r'unserialize\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)\[|["\']\s*\.\s*\$)',
     "严重"),
    
    # SSRF
    ("SSRF",
     r'(?:file_get_contents|curl_exec|curl_multi_exec)\s*\([^)]{0,100}\$_(?:GET|POST|REQUEST)',
     "高危"),
    
    # 反射型XSS
    ("反射型XSS",
     r'echo\s+["\'].*?["\']\s*\.\s*\$_(?:GET|POST|REQUEST)',
     "中危"),
    
    # 硬编码密码
    ("硬编码密钥",
     r"['\"](?:password|passwd|pwd|secret|api_key|apikey|token)['\"]\s*[=:]=?\s*['\"][a-zA-Z0-9!@#$%^&*]{8,}['\"]",
     "高危"),
    
    # 不安全的文件上传
    ("文件上传(无校验)",
     r'move_uploaded_file\s*\([^)]{0,200}\$_(?:FILES|GET|POST|REQUEST)',
     "高危"),
    
    # eval/assert
    ("代码执行(eval)",
     r'(?:eval|assert|create_function|preg_replace)\s*\([^)]{0,100}\$_(?:GET|POST|REQUEST)',
     "严重"),
]

# PHP文件敏感函数
SENSITIVE_FUNCS = [
    "shell_exec", "exec", "system", "passthru", "popen", 
    "eval", "assert", "create_function",
    "file_put_contents", "fwrite", "fputs", 
    "unserialize", "extract",
    "move_uploaded_file",
    "include", "require",
    "curl_exec", "curl_multi_exec",
]

def audit_php_file(filepath):
    """审计单个PHP文件"""
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
    except:
        return []
    
    findings = []
    
    # 按行检查，提供行号
    lines = content.split('\n')
    
    for pattern_name, pattern, severity in VULN_PATTERNS:
        for i, line in enumerate(lines, 1):
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                # 去重 - 同一个文件同一模式只报一次
                already = any(f[0] == pattern_name for f in findings)
                if not already:
                    ctx_start = max(0, i-2)
                    ctx_end = min(len(lines), i+3)
                    context = '\n'.join(f"{j}: {lines[j-1]}" for j in range(ctx_start+1, ctx_end+1))
                    findings.append((pattern_name, severity, filepath, i, context))
                    break  # 一个模式一个文件只报一次
    
    return findings

def audit_project(project_name, repo_url, local_dir):
    """下载并审计一个项目"""
    log(f"正在下载: {project_name} ({repo_url})")
    out, err, code = run(f'git clone --depth 1 "{repo_url}" "{local_dir}" 2>&1 | tail -2', timeout=60)
    
    if not os.path.exists(local_dir):
        log(f"  下载失败: {err[:100]}")
        return []
    
    log(f"  代码审计中...")
    
    # 找所有PHP文件
    php_files = []
    for root, dirs, files in os.walk(local_dir):
        # 跳过vendor/test目录
        skip = False
        for skip_dir in ['vendor', 'test', 'tests', 'example', 'examples', 'demo', 'Documentation', 'doc']:
            if skip_dir in root.split('/'):
                skip = True
                break
        if skip:
            continue
        for f in files:
            if f.endswith('.php'):
                php_files.append(os.path.join(root, f))
    
    log(f"  发现 {len(php_files)} 个PHP文件")
    
    findings = []
    for pf in php_files:
        try:
            res = audit_php_file(pf)
            findings.extend(res)
        except:
            continue
    
    log(f"  发现 {len(findings)} 个潜在漏洞")
    
    for f_name, sev, f_path, line, ctx in findings:
        rel_path = os.path.relpath(f_path, local_dir)
        detail = f"项目: {project_name}\n文件: {rel_path}:{line}\n\n上下文:\n{ctx}"
        save_finding(f"{f_name}_{project_name}", detail, sev)
    
    return findings

if __name__ == "__main__":
    log("=" * 50)
    log("PHP代码批量审计引擎")
    log("=" * 50)
    
    projects = [
        # 小型PHP项目 - 代码质量通常较差
        ("PHPCMS v9.6.3", "https://gitee.com/phpcms/phpcms.git", "/tmp/audit_phpcms"),
        ("YzmCMS", "https://gitee.com/yzmcms/yzmcms.git", "/tmp/audit_yzmcms"),
        ("CmsEasy", "https://gitee.com/ce_teams/CmsEasy.git", "/tmp/audit_cmseasy"),
        ("蝉知CMS", "https://gitee.com/chanzhi/chanzhi.git", "/tmp/audit_chanzhi"),
        ("Discuz! Q", "https://gitee.com/Discuz/Discuz-Q.git", "/tmp/audit_discuzq"),
        ("迅睿CMS", "https://gitee.com/dayrui/xunruicms.git", "/tmp/audit_xunrui"),
        ("YiAdmin", "https://gitee.com/yfcmf/YiAdmin.git", "/tmp/audit_yiadmin"),
        ("PbootCMS", "https://gitee.com/hnaoyun/PbootCMS.git", "/tmp/audit_pbootcms"),
    ]
    
    total_finds = 0
    
    for name, repo, local_dir in projects:
        try:
            finds = audit_project(name, repo, local_dir)
            total_finds += len(finds)
        except Exception as e:
            log(f"  审计失败: {e}")
        log("")
    
    log(f"\n总发现: {total_finds} 个潜在漏洞")
    log(f"结果保存在: {RESULTS_DIR}/")