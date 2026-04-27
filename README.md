# 🤖 Bounty Hunter - 全自动漏洞挖掘引擎

自动化挖掘Web漏洞、代码审计、信息泄露，自动提交漏洞盒子。

## 工具
- `tools/auto_bounty.py` - Web漏洞自动扫描（nmap+dirb+nikto）
- `tools/poc_scanner.py` - 已知POC验证（ThinkPHP RCE / Spring Boot / Log4j / Git泄露）
- `tools/php_audit.py` - PHP项目代码安全审计（SQL注入/命令执行/文件包含）

## 已发现
- 阿里云AccessKey泄露（LTAI5t7f73KRxrwL9Q）
- OpenAI API Key泄露
- 丁香园子域名枚举
- 联想/OPPO/vivo/理想汽车等SRC探测

## 工作流程
1. GitHub代码搜索 → 凭证/密钥泄露
2. PHP项目代码审计 → SQL注入/命令执行
3. 公开POC验证 → 批量漏洞检测
4. 漏洞盒子提交 → 领取赏金

## 安装依赖
```bash
sudo apt install nmap nikto dirb wfuzz
pip install requests beautifulsoup4
```

## 使用
```bash
python3 tools/auto_bounty.py     # 基础扫描
python3 tools/poc_scanner.py     # POC验证
python3 tools/php_audit.py       # 代码审计
```
