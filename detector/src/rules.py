# src/rules.py
import re
from typing import List, Tuple

# ============================================================
# 规则定义：{label: [正则列表]}
# ============================================================
RULES = {
    "xss": [
        r"<\s*script[^>]*>\s*[^<\s]",          # <script> 后紧跟执行内容（排除纯引外部js）
        r"<\s*script[^>]*>[^<]*?(alert|eval|prompt|confirm|document\.|window\.)",
        r"<\s*/\s*script",
        r"javascript\s*:(?!\s*void\s*[\(\"'])",  # javascript: 伪协议（排除 js 中常见的 void(0)）
        r"vbscript\s*:",
        r"data\s*:\s*text/html",
        r"document\s*\.\s*cookie",
        r"document\s*\.\s*write",
        r"window\s*\.\s*location",
        r"eval\s*\(",
        r"alert\s*\(",
        r"prompt\s*\(",
        r"confirm\s*\(",
        r"<\s*img[^>]+onerror",
        r"<\s*svg[^>]*onload",
        r"<\s*iframe[^>]*(srcdoc|javascript:|onload)",
        r"<\s*body[^>]+onload",
        r"<\s*body[^>]+onpageshow",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=\s*[\"']?\s*(alert|eval|location|document\.|window\.)",
        r"onmouseover\s*=",
        r"onfocus\s*=",
        r"onblur\s*=",
        r"onstart\s*=",
        r"onpageshow\s*=",
        r"expression\s*\(",
        r"fromCharCode",
        r"String\.fromCharCode",
    ],
    "sqli": [
        r"'\s*or\s+1\s*=\s*1",
        r"'\s*or\s+'1'\s*=\s*'1",
        r"'\s*or\s+'\w+'\s*=\s*'\w+",
        r"union\s+select",
        r"union\s+all\s+select",
        r"information_schema",
        r"sleep\s*\(",
        r"benchmark\s*\(",
        r"pg_sleep\s*\(",
        r"waitfor\s+delay",
        r"xp_cmdshell",
        r"load_file\s*\(",
        r"into\s+outfile",
        r"@@version",
        # 注意：以下三条原为 "'\s*--"、"/\*\*/"、"'\s*#"，会误命中 HTML 属性值
        # （例如 <Img sRc='#' Onerror=...> 里的 '#' 被判成 MySQL 注释符）。
        # 按《问题-10.20》要求：单字符 # / ' / -- 必须与 SQL 语义组合才告警。
        r"'\s*(?:--|#)[\s\x00]*$",                 # 引号+注释符且位于串尾（典型注入截断）
        r"(?:^|\s)--\s*$",                         # 独立的注释符结尾
        r"(?:^|\s)'(?:\s*--|\s*#)",                # 前面是 SQL 语句起点的引号+注释
        r"(?<![A-Za-z0-9_/*])/\*\*/",              # 独立的内联注释（非 a/*/b 这类）
        # --- 以下为补充规则（针对原规则漏报的常见形态）---
        r"group\s+by\s+[\w\.]+\s+having\b",       # group by ... having 布尔盲注
        r"\bhaving\s+\d+\s*=\s*\d+",              # having 1=1
        r"\buser\s*\(\s*\)",                      # user() 函数探测
        r"\bcurrent_user\b",                      # current_user
        r"\bdatabase\s*\(\s*\)",                  # database()
        r"\bversion\s*\(\s*\)",                   # version()
        r"\bconcat\s*\(",                         # concat() 拼接
        r"\bextractvalue\s*\(",                   # 报错注入
        r"\bupdatexml\s*\(",                      # 报错注入
        r"\bexp\s*\(\s*~",                        # 报错注入 exp(~)
        r"\bfloor\s*\(\s*rand\s*\(",              # 报错注入 floor(rand())
        r"\bord\s*\(|\bascii\s*\(|\bchar\s*\(",   # 盲注字符函数
        r"\bsubstring\s*\(|\bsubstr\s*\(|\bmid\s*\(",
        r"\blimit\s+\d+\s*,\s*\d+",               # limit 0,1 逐位猜解
        r"\bselect\b[^;]{0,80}\bfrom\b",          # 完整 select ... from 语义
        r"\binsert\s+into\b|\bupdate\b.+\bset\b|\bdelete\s+from\b",
        r"\bdrop\s+table\b|\btruncate\s+table\b",
        # 恒真条件：要求 SQL 上下文（引号/注释/分号/结尾），
        # 否则普通英文单词内部也会误命中（例如 ".DS_Store" 里的 "or"）
        r"\bor\s+\d+\s*=\s*\d+\s*(?:--|#|/\*|;|$)",
        r"['\"`)]\s*or\s+\d+\s*=\s*\d+",
        r"\band\s+\d+\s*=\s*\d+\s*(?:--|#|/\*|;|$)",
        r"['\"`)]\s*and\s+\d+\s*=\s*\d+",
        r"\bunion\b[^;]{0,40}\bselect\b",         # union ... select 跨词
        r";\s*--",                                # 语句截断
        r"\badmin'\s*--",                         # 经典登录绕过
        r"\bexec\s*\(|\bexecute\s*\(",
        r"\bcase\s+when\b",                       # case when 盲注
        r"\bif\s*\(\s*\d+\s*=",                   # if(1=1,..) 盲注
        r"0x[0-9a-f]{6,}",                        # 十六进制绕过
        r"\bchar\s*\(\s*\d+",                     # char() 构造字符串
    ],
    "path_traversal": [
        # 只保留真正的"目录穿越语法"特征（../ 及其编码变形）
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%2f",
        r"\.\.%5c",
        r"%252e%252e",
        r"\.\.;/",
        r"\.\.//",
        r"file:///",
    ],
    "sensitive_path": [
        # 敏感文件/目录探测：靠文件名/路径识别，不要求出现 ../
        # —— 系统敏感文件（Linux）
        r"/etc/passwd",
        r"/etc/shadow",
        r"/etc/hosts",
        r"/etc/group",
        r"/etc/sudoers",
        r"/etc/ssh/",
        r"/proc/self/",
        r"/proc/version",
        r"/sys/kernel/",
        r"/var/log/",
        r"/var/www/",
        r"/usr/local/etc/",
        r"/root/\.ssh/",
        r"/\.ssh/",
        r"/\.bash_history",
        r"/id_rsa",
        r"(?:^|/)id_rsa",
        # —— 系统敏感文件（Windows）
        r"c:\\windows\\win\.ini",
        r"c:\\windows\\system32\\config\\sam",
        r"c:\\windows\\system32\\drivers\\etc\\hosts",
        r"c:\\windows\\repair\\",
        r"c:\\inetpub\\",
        r"c:\\xampp\\",
        r"c:\\users\\.*\\\.ssh\\",
        r"c:\\users\\.*\\desktop\\",
        # —— 版本控制与配置文件（前导斜杠可选，兼容 ".env" 这类写法）
        r"(?:^|/)\.git/",
        r"(?:^|/)\.svn/",
        r"(?:^|/)\.hg/",
        r"(?:^|/)\.bzr/",
        r"(?:^|/)\.env\b",
        r"(?:^|/)wp-config\.php",
        r"(?:^|/)config\.php",
        r"(?:^|/)configuration\.php",
        r"(?:^|/)config\.inc\.php",
        r"(?:^|/)web\.config",
        r"(?:^|/)appsettings\.json",
        r"(?:^|/)application\.(yml|properties)",
        r"(?:^|/)bootstrap\.(yml|properties)",
        r"(?:^|/)\.htaccess",
        r"(?:^|/)\.DS_Store",
        r"(?:^|/)Thumbs\.db",
        r"(?:^|/)php\.ini",
        r"\.php~",
        # —— 管理入口与信息泄露点
        r"(?:^|/)phpmyadmin",
        r"(?:^|/)pma/",
        r"(?:^|/)adminer",
        r"(?:^|/)swagger-ui",
        r"(?:^|/)actuator",
        r"(?:^|/)phpinfo",
        r"(?:^|/)server-status",
        r"/\.well-known/",
        r"(?:^|/)backup",
        r"(?:^|/)dump\.sql",
        r"(?:^|/)database\.(sql|yml|bak)",
        r"\b(backup|dump|database)\.sql\b",
        # —— 协议包装器
        r"php://filter",
        r"php://input",
        r"expect://",
        r"data://",
        # —— 云元数据
        r"169\.254\.169\.254",
    ],
    "scanner": [
        # 自动化扫描器 / 攻击工具指纹（主要来自 User-Agent 与请求头）
        r"\bsqlmap\b",
        r"\bnikto\b",
        r"\bnmap\b|\bnmaplowercheck\b",
        r"\bmasscan\b",
        r"\bzmap\b",
        r"\bnuclei\b",
        r"\bgobuster\b",
        r"\bdirbuster\b",
        r"\bdirb\b",
        r"\bwfuzz\b",
        r"\bffuf\b",
        r"\bzgrab\b",
        r"\bwpscan\b",
        r"\bjoomscan\b",
        r"\bwhatweb\b",
        r"\bacunetix\b|\bawvs\b",
        r"\bappscan\b",
        r"\bnetsparker\b",
        r"\bopenvas\b",
        r"\bw3af\b",
        r"\bmetasploit\b",
    ],
}


# ============================================================
# 规则描述映射（把正则变成人类可读的短句）
# ============================================================
RULE_DESCRIPTIONS = {
    # XSS
    r"<\s*script[^>]*>\s*[^<\s]": "检测到 <script> 标签内联脚本",
    r"<\s*script[^>]*>[^<]*?(alert|eval|prompt|confirm|document\.|window\.)":
        "检测到 <script> 标签内的执行代码",
    r"<\s*/\s*script": "检测到 </script> 闭合标签",
    r"onerror\s*=": "检测到 onerror 事件属性",
    r"onload\s*=": "检测到 onload 事件属性",
    r"onclick\s*=\s*[\"']?\s*(alert|eval|location|document\.|window\.)":
        "检测到 onclick 事件中的执行代码",
    r"onmouseover\s*=": "检测到 onmouseover 事件属性",
    r"onfocus\s*=": "检测到 onfocus 事件属性",
    r"onblur\s*=": "检测到 onblur 事件属性",
    r"onstart\s*=": "检测到 onstart 事件属性",
    r"onpageshow\s*=": "检测到 onpageshow 事件属性",
    r"javascript\s*:(?!\s*void\s*[\(\"'])": "检测到 javascript: 伪协议",
    r"alert\s*\(": "检测到 alert() 弹窗函数",
    r"eval\s*\(": "检测到 eval() 代码执行",
    r"prompt\s*\(": "检测到 prompt() 弹窗函数",
    r"confirm\s*\(": "检测到 confirm() 弹窗函数",
    r"document\s*\.\s*cookie": "尝试读取 Cookie",
    r"document\s*\.\s*write": "尝试调用 document.write 写入页面",
    r"window\s*\.\s*location": "尝试操作 window.location 跳转",
    r"vbscript\s*:": "检测到 vbscript: 伪协议",
    r"data\s*:\s*text/html": "检测到 data:text/html 伪协议",
    r"expression\s*\(": "检测到 CSS expression() 表达式",
    r"fromCharCode": "检测到 fromCharCode 字符构造",
    r"String\.fromCharCode": "检测到 String.fromCharCode 字符构造",
    r"<\s*img[^>]+onerror": "检测到 img 标签的 onerror 事件",
    r"<\s*svg[^>]*onload": "检测到 svg 标签的 onload 事件",
    r"<\s*iframe[^>]*(srcdoc|javascript:|onload)": "检测到 iframe 标签的可执行属性",
    r"<\s*body[^>]+onload": "检测到 body 标签的 onload 事件",
    r"<\s*body[^>]+onpageshow": "检测到 body 标签的 onpageshow 事件",

    # SQLi
    r"'\s*or\s+1\s*=\s*1": "检测到 SQL 注入的恒真条件",
    r"'\s*or\s+'1'\s*=\s*'1": "检测到 SQL 注入的字符串恒等式",
    r"'\s*or\s+'\w+'\s*=\s*'\w+": "检测到 SQL 注入的字符串恒等式",
    r"union\s+select": "检测到 SQL 注入的 UNION SELECT",
    r"union\s+all\s+select": "检测到 SQL 注入的 UNION ALL SELECT",
    r"information_schema": "尝试读取数据库元数据 information_schema",
    r"sleep\s*\(": "检测到 SQL 时间盲注函数 sleep()",
    r"benchmark\s*\(": "检测到 SQL 时间盲注函数 benchmark()",
    r"pg_sleep\s*\(": "检测到 PostgreSQL 时间盲注函数 pg_sleep()",
    r"waitfor\s+delay": "检测到 SQL Server 时间盲注 waitfor delay",
    r"xp_cmdshell": "检测到 SQL Server 命令执行 xp_cmdshell",
    r"load_file\s*\(": "检测到文件读取函数 load_file()",
    r"into\s+outfile": "检测到文件写入 into outfile",
    r"@@version": "尝试读取数据库版本 @@version",
    r"'\s*--": "检测到 SQL 注释符 --",
    r"/\*\*/": "检测到 SQL 内联注释 /**/",
    r"'\s*#": "检测到 MySQL 注释符 #",
    # --- 新增 SQLi 规则描述 ---
    r"group\s+by\s+[\w\.]+\s+having\b": "检测到 group by ... having 布尔盲注",
    r"\bhaving\s+\d+\s*=\s*\d+": "检测到 having 恒真条件盲注",
    r"\buser\s*\(\s*\)": "检测到数据库函数 user() 探测",
    r"\bcurrent_user\b": "检测到 current_user 探测",
    r"\bdatabase\s*\(\s*\)": "检测到数据库函数 database() 探测",
    r"\bversion\s*\(\s*\)": "检测到数据库函数 version() 探测",
    r"\bconcat\s*\(": "检测到 concat() 字符串拼接",
    r"\bextractvalue\s*\(": "检测到报错注入函数 extractvalue()",
    r"\bupdatexml\s*\(": "检测到报错注入函数 updatexml()",
    r"\bexp\s*\(\s*~": "检测到报错注入 exp(~) 技巧",
    r"\bfloor\s*\(\s*rand\s*\(": "检测到报错注入 floor(rand()) 技巧",
    r"\bord\s*\(|\bascii\s*\(|\bchar\s*\(": "检测到盲注字符函数 ord()/ascii()/char()",
    r"\bsubstring\s*\(|\bsubstr\s*\(|\bmid\s*\(": "检测到盲注截取函数 substring()/substr()/mid()",
    r"\blimit\s+\d+\s*,\s*\d+": "检测到 limit 逐位猜解",
    r"\bselect\b.*\bfrom\b": "检测到 select ... from 完整查询语句",
    r"\binsert\s+into\b|\bupdate\b.+\bset\b|\bdelete\s+from\b": "检测到增删改 SQL 语句",
    r"\bdrop\s+table\b|\btruncate\s+table\b": "检测到破坏性 SQL 语句 drop/truncate",
    r"\bor\s+\d+\s*=\s*\d+": "检测到 or 1=1 恒真条件",
    r"\band\s+\d+\s*=\s*\d+": "检测到 and 1=1 恒真条件",
    r"\bunion\b.*\bselect\b": "检测到 union ... select 联合查询",
    r";\s*--": "检测到语句截断 ;--",
    r"\badmin'\s*--": "检测到经典登录绕过 admin'--",
    r"\bexec\s*\(|\bexecute\s*\(": "检测到 exec/execute 命令执行",
    r"\bcase\s+when\b": "检测到 case when 盲注",
    r"\bif\s*\(\s*\d+\s*=": "检测到 if() 布尔盲注",
    r"0x[0-9a-f]{6,}": "检测到十六进制编码绕过",
    r"\bchar\s*\(\s*\d+": "检测到 char() 构造字符串",

    # Path Traversal（仅目录穿越）
    r"%2e%2e%2f": "检测到 URL 编码的路径遍历 %2e%2e%2f",
    r"%2e%2e/": "检测到 URL 编码的路径遍历 %2e%2e/",
    r"\.\.%2f": "检测到混合编码的路径遍历 ..%2f",
    r"\.\.%5c": "检测到混合编码的路径遍历 ..%5c",
    r"%252e%252e": "检测到双重编码的路径遍历",
    r"\.\.;/": "检测到 ..;/  路径遍历绕过",
    r"\.\.//": "检测到 ....// 路径遍历绕过",
    r"/root/\.ssh/id_rsa": "试图读取 SSH 私钥 id_rsa",

    # Sensitive Path（敏感文件/目录探测）
    r"/\.git/": "试图读取 Git 版本库敏感文件",
    r"/\.svn/": "试图读取 SVN 元数据",
    r"/\.hg/": "试图读取 Mercurial 元数据",
    r"/\.bzr/": "试图读取 Bazaar 元数据",
    r"/\.env\b": "试图读取环境变量配置文件 .env",
    r"/wp-config\.php": "试图读取 WordPress 配置文件",
    r"/config\.php": "试图读取 PHP 配置文件",
    r"/configuration\.php": "试图读取配置文件 configuration.php",
    r"/config\.inc\.php": "试图读取配置文件 config.inc.php",
    r"/web\.config": "试图读取 Web 配置文件 web.config",
    r"/appsettings\.json": "试图读取 .NET 配置 appsettings.json",
    r"/application\.(yml|properties)": "试图读取 Spring 配置文件",
    r"/bootstrap\.(yml|properties)": "试图读取 Spring 引导配置",
    r"/\.htaccess": "试图读取 Apache 配置 .htaccess",
    r"/\.DS_Store": "试图读取 macOS 目录索引 .DS_Store",
    r"/Thumbs\.db": "试图读取 Windows 缩略图缓存 Thumbs.db",
    r"/phpmyadmin": "探测 phpMyAdmin 管理入口",
    r"/pma/": "探测 phpMyAdmin 简写入口 /pma/",
    r"/adminer": "探测 Adminer 数据库管理入口",
    r"/swagger-ui": "探测 Swagger 接口文档",
    r"/actuator": "探测 Spring Actuator 端点",
    r"/phpinfo": "探测 phpinfo 信息泄露页",
    r"/dump\.sql": "试图下载数据库导出文件 dump.sql",
    r"/backup": "探测备份目录",
    r"/database\.(sql|yml|bak)": "试图下载数据库文件",
    r"/id_rsa": "试图读取 SSH 私钥",
    r"/\.ssh/": "试图读取 .ssh 目录",
    r"/server-status": "探测 Apache server-status",
    r"/\.well-known/": "探测 .well-known 目录",

    # Path Traversal / 敏感系统文件（补回描述）
    r"\.\./": "检测到路径遍历攻击 ../",
    r"\.\.\\": "检测到路径遍历攻击 ..\\",
    r"file:///": "检测到 file:// 本地文件读取",

    '(?:^|/)\\.git/': '命中敏感路径探测特征: .git/',
    '(?:^|/)\\.svn/': '命中敏感路径探测特征: .svn/',
    '(?:^|/)\\.hg/': '命中敏感路径探测特征: .hg/',
    '(?:^|/)\\.bzr/': '命中敏感路径探测特征: .bzr/',
    '(?:^|/)\\.env\\b': '命中敏感路径探测特征: .env',
    '(?:^|/)wp-config\\.php': '命中敏感路径探测特征: wp-config.php',
    '(?:^|/)config\\.php': '命中敏感路径探测特征: config.php',
    '(?:^|/)configuration\\.php': '命中敏感路径探测特征: configuration.php',
    '(?:^|/)config\\.inc\\.php': '命中敏感路径探测特征: config.inc.php',
    '(?:^|/)web\\.config': '命中敏感路径探测特征: web.config',
    '(?:^|/)appsettings\\.json': '命中敏感路径探测特征: appsettings.json',
    '(?:^|/)application\\.(yml|properties)': '命中敏感路径探测特征: application.(yml|properties',
    '(?:^|/)bootstrap\\.(yml|properties)': '命中敏感路径探测特征: bootstrap.(yml|properties',
    '(?:^|/)\\.htaccess': '命中敏感路径探测特征: .htaccess',
    '(?:^|/)\\.DS_Store': '命中敏感路径探测特征: .DS_Store',
    '(?:^|/)Thumbs\\.db': '命中敏感路径探测特征: Thumbs.db',
    '(?:^|/)php\\.ini': '命中敏感路径探测特征: php.ini',
    '(?:^|/)phpmyadmin': '命中敏感路径探测特征: phpmyadmin',
    '(?:^|/)pma/': '命中敏感路径探测特征: pma/',
    '(?:^|/)adminer': '命中敏感路径探测特征: adminer',
    '(?:^|/)swagger-ui': '命中敏感路径探测特征: swagger-ui',
    '(?:^|/)actuator': '命中敏感路径探测特征: actuator',
    '(?:^|/)phpinfo': '命中敏感路径探测特征: phpinfo',
    '(?:^|/)server-status': '命中敏感路径探测特征: server-status',
    '(?:^|/)backup': '命中敏感路径探测特征: backup',
    '(?:^|/)dump\\.sql': '命中敏感路径探测特征: dump.sql',
    '(?:^|/)database\\.(sql|yml|bak)': '命中敏感路径探测特征: database.(sql|yml|bak',
    '\\bselect\\b[^;]{0,80}\\bfrom\\b': '命中SQL 注入特征: select[;]{0,80}from',
    '\\bor\\s+\\d+\\s*=\\s*\\d+\\s*(?:--|#|/\\*|;|$)': '检测到 SQL 恒真条件 or N=N',
    '[\'\\"`)]\\s*or\\s+\\d+\\s*=\\s*\\d+': '检测到带引号的 SQL 布尔注入 or 条件',
    '\\band\\s+\\d+\\s*=\\s*\\d+\\s*(?:--|#|/\\*|;|$)': '检测到 SQL 恒真条件 and N=N',
    '[\'\\"`)]\\s*and\\s+\\d+\\s*=\\s*\\d+': '检测到带引号的 SQL 盲注 and 条件',
    '\\bunion\\b[^;]{0,40}\\bselect\\b': '命中SQL 注入特征: union[;]{0,40}select',
    '\\bsqlmap\\b': '命中scanner特征: sqlmap',
    '\\bnikto\\b': '命中scanner特征: nikto',
    '\\bnmap\\b|\\bnmaplowercheck\\b': '命中scanner特征: nmap|nmaplowercheck',
    '\\bmasscan\\b': '命中scanner特征: masscan',
    '\\bzmap\\b': '命中scanner特征: zmap',
    '\\bnuclei\\b': '命中scanner特征: nuclei',
    '\\bgobuster\\b': '命中scanner特征: gobuster',
    '\\bdirbuster\\b': '命中scanner特征: dirbuster',
    '\\bdirb\\b': '命中scanner特征: dirb',
    '\\bwfuzz\\b': '命中scanner特征: wfuzz',
    '\\bffuf\\b': '命中scanner特征: ffuf',
    '\\bzgrab\\b': '命中scanner特征: zgrab',
    '\\bwpscan\\b': '命中scanner特征: wpscan',
    '\\bjoomscan\\b': '命中scanner特征: joomscan',
    '\\bwhatweb\\b': '命中scanner特征: whatweb',
    '\\bacunetix\\b|\\bawvs\\b': '命中scanner特征: acunetix|awvs',
    '\\bappscan\\b': '命中scanner特征: appscan',
    '\\bnetsparker\\b': '命中scanner特征: netsparker',
    '\\bopenvas\\b': '命中scanner特征: openvas',
    '\\bw3af\\b': '命中scanner特征: w3af',
    '\\bmetasploit\\b': '命中scanner特征: metasploit',
    "'\\s*(?:--|#)[\\s\\x00]*$": "命中SQL 注入特征: ' [sx00]*",
    '(?:^|\\s)--\\s*$': '命中SQL 注入特征: --',
    "(?:^|\\s)'(?:\\s*--|\\s*#)": "命中SQL 注入特征: '",
    '(?<![A-Za-z0-9_/*])/\\*\\*/': '命中SQL 注入特征: /**/',
    '(?:^|/)id_rsa': '命中敏感路径探测特征: id_rsa',
    # Sensitive Path 补充描述
    r"c:\\windows\\win\.ini": "试图读取 Windows 敏感文件 win.ini",
    r"php://filter": "检测到 PHP 伪协议 php://filter",
    r"php://input": "检测到 PHP 伪协议 php://input",
    r"169\.254\.169\.254": "试图访问云元数据服务 169.254.169.254",
    r"/etc/hosts": "试图读取系统文件 /etc/hosts",
    r"/etc/passwd": "试图读取系统敏感文件 /etc/passwd",
    r"/etc/shadow": "试图读取系统敏感文件 /etc/shadow",
    r"/etc/group": "试图读取系统文件 /etc/group",
    r"/etc/sudoers": "试图读取 sudo 配置 /etc/sudoers",
    r"/etc/ssh/": "试图读取 SSH 服务配置",
    r"/proc/self/": "试图读取进程信息 /proc/self/",
    r"/proc/version": "试图读取内核版本 /proc/version",
    r"/sys/kernel/": "试图读取内核参数 /sys/kernel/",
    r"/var/log/": "试图读取系统日志",
    r"/var/www/": "试图读取 Web 根目录文件",
    r"/usr/local/etc/": "试图读取本地服务配置",
    r"/root/\.ssh/": "试图读取 root 的 SSH 目录",
    r"/\.bash_history": "试图读取命令历史 .bash_history",
    r"c:\\windows\\system32\\config\\sam": "试图读取 Windows 账户数据库 SAM",
    r"c:\\windows\\system32\\drivers\\etc\\hosts": "试图读取 Windows hosts 文件",
    r"c:\\windows\\repair\\": "试图读取 Windows 修复目录（含备份 SAM）",
    r"c:\\inetpub\\": "试图读取 IIS 站点目录",
    r"c:\\xampp\\": "试图读取 XAMPP 配置文件",
    r"c:\\users\\.*\\\.ssh\\": "试图读取用户 SSH 密钥目录",
    r"c:\\users\\.*\\desktop\\": "试图读取用户桌面文件",
    r"/php\.ini": "试图读取 PHP 配置文件 php.ini",
    r"\.php~": "试图读取编辑器备份文件 .php~",
    r"\b(backup|dump|database)\.sql\b": "试图下载数据库备份文件",
    r"expect://": "检测到 expect:// 协议包装器",
    r"data://": "检测到 data:// 协议包装器",
}


# ============================================================
# 已知安全路径（白名单）：用于抵消模型对"短路径"的过判
# ============================================================
# 背景：训练集 normal 中几乎没有 WEB 路径样本（5610 条里仅 18 条像路径），
# 而 sensitive_path 几乎全是短路径，导致模型把任何短路径都倾向判成
# sensitive_path（实测 "/" 与 "/index.php" 的攻击概率高达 1.0）。
# 命中白名单时给一个负分偏移，把累加分拉回可疑线以下。
#
# 注意：只匹配**完整路径**（忽略查询串、大小写不敏感），不做子串匹配，
# 因此 "/.git/config"、"/phpmyadmin/index.php" 这类攻击路径不会被放行。
BENIGN_PATHS = [
    r"/",
    r"/index\.(php|html|htm|jsp|asp|aspx)",
    r"/home/?", r"/about(-us)?/?", r"/contact/?",
    r"/login/?", r"/logout/?", r"/register/?", r"/signup/?", r"/signin/?",
    r"/search/?", r"/dashboard/?", r"/profile/?", r"/settings/?", r"/account/?",
    r"/user(s)?(/[\w\-]+)?/?", r"/news(/[\w\-/]+)?/?", r"/blog(/[\w\-/]+)?/?",
    r"/products?(/[\w\-]+)?/?", r"/product/[\w\-]+/?", r"/cart/?", r"/checkout/?",
    r"/orders?(/[\w\-]+)?/?", r"/services/?", r"/solutions/?", r"/support/?",
    r"/help/?", r"/faq/?", r"/terms/?", r"/privacy/?", r"/policy/?",
    r"/sitemap(_index)?\.xml", r"/robots\.txt", r"/favicon\.ico",
    r"/feed/?", r"/rss\.xml",
    r"/api(/[\w\-\.]+)*/?", r"/healthz?/?", r"/ping/?", r"/status/?",
    r"/version/?", r"/metrics/?",
    r"/static/[\w\-/\.]+", r"/assets/[\w\-/\.]+", r"/css/[\w\-/\.]+",
    r"/js/[\w\-/\.]+", r"/img/[\w\-/\.]+", r"/images/[\w\-/\.]+",
    r"/fonts/[\w\-/\.]+", r"/uploads/[\w\-/\.]+", r"/media/[\w\-/\.]+",
    r"/downloads?/[\w\-/\.]+", r"/files/[\w\-/\.]+",
    r"/docs?(/[\w\-/\.]+)?/?", r"/documentation/?",
    r"/administrator/?", r"/manage(ment)?/?", r"/backend/?",
    r"/cpanel/?", r"/webmail/?",
    r"/category/[\w\-]+/?", r"/tag/[\w\-]+/?", r"/archive(/[\w\-/]+)?/?",
    r"/page/\d+/?", r"/en(/[\w\-/]+)?/?", r"/zh-cn(/[\w\-/]+)?/?",
    r"/store(/[\w\-/]+)?/?", r"/catalog(/[\w\-/]+)?/?", r"/gallery/?",
    r"/portfolio/?", r"/team/?", r"/careers/?", r"/pricing/?",
    r"/testimonials/?", r"/events/?", r"/calendar/?", r"/resources/?",
    r"/tutorials/?", r"/community/?", r"/forum/?", r"/topic/[\w\-]+/?",
    r"/thread/[\w\-]+/?", r"/review/[\w\-]+/?",
]

BENIGN_PENALTY = 20   # 命中白名单时从累加分中扣减的分值


def is_benign_path(path: str) -> bool:
    """判断路径是否命中"已知安全路径"白名单（忽略查询串、大小写不敏感）。"""
    p = str(path or "").split("?")[0].strip()
    if not p:
        return False
    for pat in BENIGN_PATHS:
        if re.fullmatch(pat, p, re.IGNORECASE):
            return True
    return False


# ============================================================
# 规则类别优先级与建议权重分
# ============================================================
# 数字越小优先级越高（越具体）。利用类特征比探测类更具决定性。
LABEL_PRIORITY = {
    "sqli": 1,
    "xss": 2,
    "scanner": 3,
    "path_traversal": 4,
    "sensitive_path": 5,
}

# 命中该类规则时建议累加的分值，对齐蜜罐权重表量纲：
# 探测类 +15~22，利用类 +18~25，扫描器指纹 +22。
# sensitive_path 取 20：访问 /root/.ssh/、/var/log/、/proc/self/ 这类
# 系统敏感文件已属明确威胁，单独应能越过 20 分可疑线。
RULE_POINTS = {
    "xss": 22,
    "sqli": 25,
    "scanner": 22,
    "path_traversal": 22,
    "sensitive_path": 20,
}


def get_rule_description(pattern: str) -> str:
    """获取规则的友好描述，找不到则返回原 pattern"""
    return RULE_DESCRIPTIONS.get(pattern, f"命中规则: {pattern}")


def match_rules(text: str) -> List[Tuple[str, str]]:
    """
    返回命中的规则列表，格式 [(label, pattern), ...]，按类别特异性降序排列。

    优先级说明：利用类（xss/sqli）特征最具体，排在探测类（path_traversal/
    sensitive_path）之前，避免样本同时含多类特征时被判成较弱的类别。
    """
    hits = []
    for label, patterns in RULES.items():
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                hits.append((label, p))
    hits.sort(key=lambda x: LABEL_PRIORITY.get(x[0], 99))
    return hits


def match_rules_with_score(text: str) -> List[Tuple[str, str, int]]:
    """
    返回命中的规则及建议权重分，格式 [(label, pattern, points), ...]。
    供蜜罐"多特征加权累加"使用；points 对齐蜜罐权重表量纲。
    """
    out = []
    for label, pattern in match_rules(text):
        out.append((label, pattern, RULE_POINTS.get(label, 10)))
    return out


def has_any_rule_hit(text: str) -> bool:
    return len(match_rules(text)) > 0