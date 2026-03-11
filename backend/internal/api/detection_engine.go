package api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"obsidianwatch/management/internal/notify"
	"obsidianwatch/management/internal/store"
)

// ── Threat Signature ─────────────────────────────────────────────────────────

type ThreatSig struct {
	ID          string
	Name        string
	Description string
	Severity    int
	MITRE       string // ATT&CK technique ID
	Category    string
	Match       func(ev store.Event) bool
}

// ── Signature Library (25+ detections) ───────────────────────────────────────

var threatSignatures = []ThreatSig{

	// ── Execution ────────────────────────────────────────────────────────────

	{
		ID: "T1059.001", Name: "PowerShell Encoded Command",
		Description: "PowerShell launched with -EncodedCommand flag — common malware obfuscation technique.",
		Severity: 4, MITRE: "T1059.001", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "-enc", "-encodedcommand", "-e JAB", "-e SQB")
		},
	},
	{
		ID: "T1059.001b", Name: "PowerShell Download Cradle",
		Description: "PowerShell attempting to download and execute code from the internet.",
		Severity: 5, MITRE: "T1059.001", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "downloadstring", "downloadfile", "iex(", "invoke-expression", "webclient", "wget ", "curl ")
		},
	},
	{
		ID: "T1059.003", Name: "Suspicious CMD Execution",
		Description: "cmd.exe running with unusual flags or piped commands associated with malware.",
		Severity: 3, MITRE: "T1059.003", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && proc(ev) == "cmd.exe" &&
				containsAny(cl(ev), "/c whoami", "/c net ", "/c ipconfig", "echo %", "certutil", "bitsadmin")
		},
	},
	{
		ID: "T1218.011", Name: "Rundll32 Suspicious Execution",
		Description: "rundll32.exe used to execute code — common LOLBAS (Living Off The Land) technique.",
		Severity: 4, MITRE: "T1218.011", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "rundll32") &&
				containsAny(cl(ev), "javascript:", "vbscript:", "shell32", ",Control_RunDLL", "http")
		},
	},
	{
		ID: "T1218.005", Name: "MSHTA Execution",
		Description: "mshta.exe executing remote or local HTA — frequently used for initial access.",
		Severity: 4, MITRE: "T1218.005", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "mshta")
		},
	},
	{
		ID: "T1218.010", Name: "Regsvr32 Bypass",
		Description: "regsvr32.exe loading a remote scriptlet — Squiblydoo AppLocker bypass.",
		Severity: 5, MITRE: "T1218.010", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "regsvr32") &&
				containsAny(cl(ev), "http", "/u ", "/s ", "scrobj")
		},
	},
	{
		ID: "T1059.005", Name: "WScript/CScript Execution",
		Description: "Windows Script Host executing a script — used for malicious VBScript/JScript.",
		Severity: 3, MITRE: "T1059.005", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "wscript.exe", "cscript.exe")
		},
	},

	// ── Discovery ────────────────────────────────────────────────────────────

	{
		ID: "T1057", Name: "Process Discovery",
		Description: "Enumeration of running processes — reconnaissance activity.",
		Severity: 2, MITRE: "T1057", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "tasklist", "Get-Process", "ps aux", "qprocess")
		},
	},
	{
		ID: "T1016", Name: "Network Configuration Discovery",
		Description: "Network enumeration commands — ipconfig, netstat, arp.",
		Severity: 2, MITRE: "T1016", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "ipconfig", "netstat", "arp -a", "route print", "nslookup", "net view")
		},
	},
	{
		ID: "T1087", Name: "Account Enumeration",
		Description: "Commands used to enumerate local or domain accounts.",
		Severity: 3, MITRE: "T1087", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "net user", "net localgroup", "net group", "Get-ADUser", "whoami /all", "query user")
		},
	},
	{
		ID: "T1083", Name: "Sensitive Directory Enumeration",
		Description: "Directory listing of sensitive paths (Users, AppData, Temp).",
		Severity: 2, MITRE: "T1083", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"dir c:\\users", "dir %appdata%", "dir %temp%", "ls /etc/passwd",
				"Get-ChildItem", "tree c:\\")
		},
	},

	// ── Privilege Escalation ─────────────────────────────────────────────────

	{
		ID: "T1548.002", Name: "UAC Bypass Attempt",
		Description: "Known UAC bypass techniques detected in command line.",
		Severity: 5, MITRE: "T1548.002", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"eventvwr", "fodhelper", "sdclt", "ComputerDefaults", "bypassuac")
		},
	},
	{
		ID: "T1055", Name: "Process Injection Indicator",
		Description: "Known process injection tools or techniques detected.",
		Severity: 5, MITRE: "T1055", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "mimikatz", "procdump")
		},
	},

	// ── Credential Access ────────────────────────────────────────────────────

	{
		ID: "T1003.001", Name: "LSASS Memory Dump",
		Description: "Attempt to dump LSASS memory — credential harvesting.",
		Severity: 5, MITRE: "T1003.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "process" || ev.EventType == "file") &&
				containsAny(cl(ev)+fp(ev), "lsass", "procdump", "comsvcs.dll,MiniDump", "sekurlsa")
		},
	},
	{
		ID: "T1003.002", Name: "SAM Database Access",
		Description: "Attempt to access the SAM database — contains Windows password hashes.",
		Severity: 5, MITRE: "T1003.002", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+rk(ev)+cl(ev), `SYSTEM\CurrentControlSet\Control\Lsa`, `SAM\SAM\Domains`, "reg save hklm\\sam")
		},
	},
	{
		ID: "T1552.001", Name: "Credentials in Files Search",
		Description: "Searching for credential files or password strings.",
		Severity: 3, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"password", "findstr /si password", ".kdbx", "credential", "vault", "unattend.xml")
		},
	},
	{
		ID: "T1110", Name: "Brute Force — Multiple Failed Logons",
		Description: "Windows Event ID 4625 — failed logon (may indicate brute force).",
		Severity: 3, MITRE: "T1110", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "logon" && ev.EventID != nil && *ev.EventID == 4625
		},
	},

	// ── Lateral Movement ─────────────────────────────────────────────────────

	{
		ID: "T1021.001", Name: "RDP Lateral Movement",
		Description: "Outbound RDP connection (port 3389) — potential lateral movement.",
		Severity: 4, MITRE: "T1021.001", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "network" && ev.DstPort != nil && *ev.DstPort == 3389 && ev.Severity >= 3
		},
	},
	{
		ID: "T1021.002", Name: "SMB Lateral Movement",
		Description: "Outbound SMB connection (port 445) with high severity — potential lateral movement or ransomware spreading.",
		Severity: 4, MITRE: "T1021.002", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "network" && ev.DstPort != nil && *ev.DstPort == 445 && ev.Severity >= 4
		},
	},
	{
		ID: "T1021.004", Name: "SSH Lateral Movement",
		Description: "Outbound SSH connection (port 22) on a Windows host — uncommon, investigate.",
		Severity: 3, MITRE: "T1021.004", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "network" && ev.DstPort != nil && *ev.DstPort == 22
		},
	},
	{
		ID: "T1570", Name: "PsExec / Remote Execution Tool",
		Description: "PsExec or similar remote execution tool detected.",
		Severity: 4, MITRE: "T1570", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "psexec", "paexec", "wmiexec", "winrm")
		},
	},

	// ── Persistence ──────────────────────────────────────────────────────────

	{
		ID: "T1547.001", Name: "Run Key Persistence",
		Description: "Registry Run key modified — common persistence mechanism.",
		Severity: 4, MITRE: "T1547.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "registry" && containsAny(rk(ev),
				`\CurrentVersion\Run`, `\CurrentVersion\RunOnce`, `Policies\Explorer\Run`)
		},
	},
	{
		ID: "T1053.005", Name: "Scheduled Task Created",
		Description: "New scheduled task created — used for persistence and lateral movement.",
		Severity: 3, MITRE: "T1053.005", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "schtasks /create", "New-ScheduledTask", "at.exe ")
		},
	},
	{
		ID: "T1543.003", Name: "New Service Created",
		Description: "New Windows service installed via sc.exe or PowerShell — used for persistence.",
		Severity: 4, MITRE: "T1543.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "sc create", "New-Service", "sc.exe create")
		},
	},

	// ── Defence Evasion ──────────────────────────────────────────────────────

	{
		ID: "T1562.001", Name: "Security Tool Disabled",
		Description: "Attempt to disable Windows Defender, Firewall, or other security tools.",
		Severity: 5, MITRE: "T1562.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"Set-MpPreference -DisableRealtime", "netsh advfirewall set allprofiles state off",
				"sc stop windefend", "sc config windefend start= disabled",
				"DisableAntiSpyware", "wf.msc")
		},
	},
	{
		ID: "T1070.001", Name: "Event Log Cleared",
		Description: "Windows event log cleared — attacker covering tracks.",
		Severity: 5, MITRE: "T1070.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return (ev.EventID != nil && (*ev.EventID == 1102 || *ev.EventID == 104)) ||
				containsAny(cl(ev), "wevtutil cl", "Clear-EventLog", "clearev")
		},
	},
	{
		ID: "T1027", Name: "Obfuscated Command",
		Description: "Heavily obfuscated command detected — Base64, XOR, or character substitution.",
		Severity: 4, MITRE: "T1027", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && (
				containsAny(cl(ev), "frombase64string", "[convert]::", "char(", "chr(", "`i`e`x") ||
				strings.Count(cl(ev), "^") > 5)
		},
	},
	{
		ID: "T1036", Name: "Process Name Masquerading",
		Description: "Known system process running from unexpected location.",
		Severity: 4, MITRE: "T1036", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			trusted := []string{"svchost.exe", "lsass.exe", "explorer.exe", "winlogon.exe", "csrss.exe"}
			p := strings.ToLower(proc(ev))
			img := strings.ToLower(img(ev))
			for _, t := range trusted {
				if strings.Contains(p, t) && img != "" &&
					!containsAny(img, `\system32\`, `\syswow64\`, `\windows\`) {
					return true
				}
			}
			return false
		},
	},

	// ── Command & Control ────────────────────────────────────────────────────

	{
		ID: "T1219", Name: "Remote Access Tool — RustDesk",
		Description: "RustDesk remote access tool DNS query detected.",
		Severity: 4, MITRE: "T1219", Category: "Command & Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "dns" && containsAny(dstip(ev)+proc(ev)+cl(ev), "rustdesk")
		},
	},
	{
		ID: "T1219b", Name: "Remote Access Tool — AnyDesk/TeamViewer",
		Description: "Commercial remote access tool detected — verify if authorised.",
		Severity: 3, MITRE: "T1219", Category: "Command & Control",
		Match: func(ev store.Event) bool {
			return containsAny(proc(ev)+cl(ev)+fp(ev), "anydesk", "teamviewer", "logmein", "screenconnect", "connectwise")
		},
	},
	{
		ID: "T1572", Name: "DNS Tunnelling Indicator",
		Description: "Unusually long DNS hostname query — may indicate DNS tunnelling.",
		Severity: 4, MITRE: "T1572", Category: "Command & Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "dns" && ev.DstIP != nil && len(*ev.DstIP) > 60
		},
	},
	{
		ID: "T1071.001b", Name: "Suspicious Outbound Port",
		Description: "Outbound connection on unusual port (not 80/443/53/22/25) — possible C2.",
		Severity: 3, MITRE: "T1071.001", Category: "Command & Control",
		Match: func(ev store.Event) bool {
			if ev.EventType != "network" || ev.DstPort == nil { return false }
			p := *ev.DstPort
			return ev.Severity >= 3 && p != 80 && p != 443 && p != 53 && p != 22 && p != 25 && p != 587 && p != 3389 && p != 445 && p != 8443 && p != 8080 && p != 8443 && p > 1024
		},
	},
	{
		ID: "T1090", Name: "WPAD Proxy Discovery",
		Description: "WPAD auto-proxy discovery — can be abused for MITM attacks.",
		Severity: 3, MITRE: "T1090", Category: "Command & Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "dns" && containsAny(dstip(ev), "wpad")
		},
	},

	// ── Exfiltration ─────────────────────────────────────────────────────────

	{
		ID: "T1048", Name: "Data Exfiltration — FTP/SFTP",
		Description: "Outbound FTP connection — potential data exfiltration.",
		Severity: 4, MITRE: "T1048", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "network" && ev.DstPort != nil && (*ev.DstPort == 21 || *ev.DstPort == 990 || *ev.DstPort == 115)
		},
	},
	{
		ID: "T1041", Name: "Certutil Encode/Decode",
		Description: "Certutil used to encode/decode data — common exfiltration and download technique.",
		Severity: 4, MITRE: "T1041", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "certutil") &&
				containsAny(cl(ev), "-encode", "-decode", "-urlcache", "-f ")
		},
	},

	// ── Impact ───────────────────────────────────────────────────────────────

	{
		ID: "T1490", Name: "Shadow Copy Deletion",
		Description: "Volume Shadow Copy deletion — ransomware pre-cursor.",
		Severity: 5, MITRE: "T1490", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"vssadmin delete shadows", "wmic shadowcopy delete",
				"bcdedit /set {default} recoveryenabled No",
				"wbadmin delete catalog", "Delete-ComputerBackup")
		},
	},
	{
		ID: "T1486", Name: "Mass File Modification",
		Description: "Rapid file changes detected — potential ransomware encryption activity.",
		Severity: 5, MITRE: "T1486", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "file" && ev.Severity >= 4 &&
				containsAny(fp(ev), ".locked", ".encrypted", ".crypto", ".crypt", ".enc")
		},
	},

	// ════════════════════════════════════════════════════════════════════════
	// ── Linux Detections ─────────────────────────────────────────────────────
	// ════════════════════════════════════════════════════════════════════════

	// ── Linux Execution ──────────────────────────────────────────────────────

	{
		ID: "T1059.004", Name: "Linux Shell Pipe Execution",
		Description: "Shell interpreter executing piped commands from network — common dropper.",
		Severity: 4, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" { return false }
			isShell := containsAny(proc(ev), "bash", "sh", "zsh", "dash", "ksh")
			return isShell && containsAny(cl(ev), "| bash", "|bash", "| sh", "|sh", "/tmp/", "/dev/shm", "http://", "https://")
		},
	},
	{
		ID: "T1059.006", Name: "Python/Perl Reverse Shell",
		Description: "Python or Perl opening a socket — common reverse shell technique.",
		Severity: 5, MITRE: "T1059.006", Category: "Execution",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" { return false }
			isInterp := containsAny(proc(ev), "python", "perl", "ruby", "php", "node")
			return isInterp && containsAny(cl(ev), "socket", "connect(", "import socket", "exec(", "/dev/tcp", "subprocess")
		},
	},
	{
		ID: "T1059.004b", Name: "Netcat Reverse Shell",
		Description: "Netcat with -e or -c flag — classic reverse shell payload.",
		Severity: 5, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "nc", "ncat", "netcat") &&
				containsAny(cl(ev), " -e ", " -c ", "--exec", "-e /bin", "-e sh", "-e bash")
		},
	},
	{
		ID: "T1059.004c", Name: "Executable Dropped in /tmp",
		Description: "Process spawned from /tmp or /dev/shm — common malware staging.",
		Severity: 5, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" &&
				(containsAny(img(ev), "/tmp/", "/dev/shm/", "/var/tmp/") ||
					containsAny(cl(ev), "/tmp/", "/dev/shm/"))
		},
	},

	// ── Linux Persistence ────────────────────────────────────────────────────

	{
		ID: "T1053.003", Name: "Cron Persistence",
		Description: "Crontab written or modified — common Linux persistence mechanism.",
		Severity: 4, MITRE: "T1053.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "file" && containsAny(fp(ev), "/etc/cron", "/var/spool/cron", "crontab")) ||
				(ev.EventType == "process" && containsAny(cl(ev), "crontab -e", "crontab -l"))
		},
	},
	{
		ID: "T1543.002", Name: "New Systemd Service",
		Description: "New systemd unit file written to system directories — persistence.",
		Severity: 4, MITRE: "T1543.002", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "file" && containsAny(fp(ev),
				"/etc/systemd/system/", "/usr/lib/systemd/", "/lib/systemd/") &&
				containsAny(fp(ev), ".service", ".timer", ".socket")
		},
	},
	{
		ID: "T1546.004", Name: "Shell Profile Backdoor",
		Description: ".bashrc, .profile, or /etc/profile modified — shell-based persistence.",
		Severity: 4, MITRE: "T1546.004", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "file" && containsAny(fp(ev),
				".bashrc", ".bash_profile", ".zshrc", "/etc/profile", "/etc/bash.bashrc")
		},
	},
	{
		ID: "T1547.006", Name: "Kernel Module Inserted",
		Description: "insmod/modprobe executed — rootkit or kernel-level persistence.",
		Severity: 5, MITRE: "T1547.006", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "insmod", "modprobe") ||
				containsAny(rawStr(ev), "kernel_module_load")
		},
	},

	// ── Linux Privilege Escalation ────────────────────────────────────────────

	{
		ID: "T1548.001", Name: "SUID Binary Created",
		Description: "chmod +s or setuid bits set — SUID privilege escalation.",
		Severity: 4, MITRE: "T1548.001", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "chmod") &&
				containsAny(cl(ev), "+s", "4755", "4777", "u+s")
		},
	},
	{
		ID: "T1548.001b", Name: "Sudo Shell Escape",
		Description: "sudo used to spawn a root shell — privilege escalation.",
		Severity: 4, MITRE: "T1548.001", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "sudo") &&
				containsAny(cl(ev), "sudo su", "sudo bash", "sudo sh", "sudo -s", "sudo -i")
		},
	},

	// ── Linux Credential Access ───────────────────────────────────────────────

	{
		ID: "T1003.008", Name: "/etc/shadow Access",
		Description: "Direct read of /etc/shadow or credential dumping tools detected.",
		Severity: 5, MITRE: "T1003.008", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev), "/etc/shadow", "/etc/gshadow") ||
				(ev.EventType == "process" && containsAny(cl(ev), "unshadow", "hashcat", "john --"))
		},
	},
	{
		ID: "T1110.001b", Name: "SSH Brute Force",
		Description: "SSH authentication failure detected — possible brute force attack.",
		Severity: 4, MITRE: "T1110.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "logon" && containsAny(rawStr(ev), "ssh_failed", "Failed password", "invalid user")
		},
	},
	{
		ID: "T1552.004", Name: "SSH Private Key Access",
		Description: "Access to SSH private key files — credential theft.",
		Severity: 4, MITRE: "T1552.004", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev), "id_rsa", "id_ed25519", "id_ecdsa", "/.ssh/", ".pem")
		},
	},

	// ── Linux Defence Evasion ────────────────────────────────────────────────

	{
		ID: "T1574.006", Name: "LD_PRELOAD Injection",
		Description: "LD_PRELOAD or /etc/ld.so.preload set — shared library hijacking.",
		Severity: 5, MITRE: "T1574.006", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev)+rawStr(ev), "ld_preload", "ld.so.preload")
		},
	},
	{
		ID: "T1070.002", Name: "Linux Log Deletion",
		Description: "System logs deleted or history cleared — attacker covering tracks.",
		Severity: 5, MITRE: "T1070.002", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			if ev.EventType == "process" {
				return containsAny(cl(ev), "rm /var/log", "shred /var/log", "> /var/log",
					"history -c", "unset HISTFILE", "HISTSIZE=0", "rm -rf /var/log")
			}
			return ev.EventType == "file" && containsAny(fp(ev), "/var/log/auth", "/var/log/syslog", "/var/log/secure")
		},
	},
	{
		ID: "T1222.002", Name: "World-Writable File Created",
		Description: "chmod 777 executed — permissive file used for staging or evasion.",
		Severity: 3, MITRE: "T1222.002", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "chmod") &&
				containsAny(cl(ev), "777", "a+w", "o+w")
		},
	},

	// ── Linux Discovery ───────────────────────────────────────────────────────

	{
		ID: "T1087.001", Name: "Linux User Enumeration",
		Description: "Commands used to enumerate local users and sudo rights.",
		Severity: 2, MITRE: "T1087.001", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"cat /etc/passwd", "getent passwd", "id -a", "sudo -l", "last ", "lastlog", "w ", "who ")
		},
	},
	{
		ID: "T1046b", Name: "Linux Network Scanning",
		Description: "nmap, masscan, or netstat enumeration — network reconnaissance.",
		Severity: 3, MITRE: "T1046", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev),
				"nmap", "masscan", "zmap", "arp-scan", "netdiscover")
		},
	},

	// ── Linux C2 / Exfiltration ───────────────────────────────────────────────

	{
		ID: "T1105b", Name: "Curl/Wget Pipe to Shell",
		Description: "curl or wget piping directly to shell — dropper technique.",
		Severity: 5, MITRE: "T1105", Category: "Command & Control",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" { return false }
			return containsAny(proc(ev), "curl", "wget") &&
				containsAny(cl(ev), "| bash", "|bash", "| sh", "|sh", "| python", "exec(")
		},
	},
	{
		ID: "T1021.004b", Name: "SSH Tunnel / Port Forward",
		Description: "SSH -L/-R/-D flag — tunnelling or SOCKS proxy for C2.",
		Severity: 4, MITRE: "T1021.004", Category: "Command & Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "ssh") &&
				containsAny(cl(ev), " -L ", " -R ", " -D ", "-NfL", "-NfR", "-NfD")
		},
	},
	{
		ID: "T1048b", Name: "Data Exfiltration via curl POST",
		Description: "curl sending data with POST/upload flags — possible data exfiltration.",
		Severity: 3, MITRE: "T1048", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && proc(ev) == "curl" &&
				containsAny(cl(ev), " -d ", " --data ", " -F ", " -T ", "--upload-file", "-X POST")
		},
	},

}

// ── Helper extractors ─────────────────────────────────────────────────────────

func cl(ev store.Event) string {
	if ev.CommandLine == nil { return "" }
	return strings.ToLower(*ev.CommandLine)
}
func proc(ev store.Event) string {
	if ev.ProcessName == nil { return "" }
	return strings.ToLower(*ev.ProcessName)
}
func img(ev store.Event) string {
	if ev.ImagePath == nil { return "" }
	return strings.ToLower(*ev.ImagePath)
}
func fp(ev store.Event) string {
	if ev.FilePath == nil { return "" }
	return strings.ToLower(*ev.FilePath)
}
func rk(ev store.Event) string {
	if ev.RegKey == nil { return "" }
	return strings.ToLower(*ev.RegKey)
}
func dstip(ev store.Event) string {
	if ev.DstIP == nil { return "" }
	return strings.ToLower(*ev.DstIP)
}

func rawStr(ev store.Event) string {
	if ev.Raw == nil { return "" }
	return strings.ToLower(string(ev.Raw))
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, strings.ToLower(sub)) { return true }
	}
	return false
}

// ── Detection Engine ─────────────────────────────────────────────────────────

type DetectionEngine struct {
	db     *store.DB
	mailer *notify.Mailer
	logger *slog.Logger
}

func NewDetectionEngine(db *store.DB, mailer *notify.Mailer, logger *slog.Logger) *DetectionEngine {
	return &DetectionEngine{db: db, mailer: mailer, logger: logger}
}

func (e *DetectionEngine) Run(ctx context.Context) {
	// Catch-up: scan last 24h on first start
	e.evaluateSince(ctx, time.Now().Add(-24*time.Hour))

	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done(): return
		case <-ticker.C:   e.evaluate(ctx)
		}
	}
}

func (e *DetectionEngine) evaluate(ctx context.Context) {
	e.evaluateSince(ctx, time.Now().Add(-2*time.Minute))
}

func (e *DetectionEngine) evaluateSince(ctx context.Context, since time.Time) {
	events, _, err := e.db.QueryEvents(ctx, store.EventFilter{Since: since, Limit: 5000})
	if err != nil {
		e.logger.Warn("detection: query failed", "err", err)
		return
	}

	created := 0
	for _, ev := range events {
		for _, sig := range threatSignatures {
			if !sig.Match(ev) { continue }

			// Dedup per host per signature per hour — prevents alert storms
			hour := ev.Time.UTC().Format("2006010215")
			dedupKey := fmt.Sprintf("sig:%s:host:%s:h:%s", sig.ID, ev.Host, hour)
			exists, _ := e.db.AlertExists(ctx, dedupKey)
			if exists { continue }

			desc := fmt.Sprintf(
				"%s\n\nMITRE ATT&CK: %s | Category: %s\nHost: %s | User: %s | Process: %s\nCommand: %s",
				sig.Description,
				sig.MITRE, sig.Category,
				ev.Host, strOrDash(ev.UserName), strOrDash(ev.ProcessName), strOrDash(ev.CommandLine),
			)

			alert := store.Alert{
				Title:       fmt.Sprintf("[%s] %s", sig.MITRE, sig.Name),
				Description: desc,
				Severity:    sig.Severity,
				AgentID:     ev.AgentID,
				Host:        ev.Host,
				EventType:   ev.EventType,
				EventID:     dedupKey,
			}

			id, err := e.db.CreateAlert(ctx, alert)
			if err != nil { continue }
			created++

			alert.CreatedAt = time.Now()
			if e.mailer.Enabled() && sig.Severity >= e.mailer.MinSeverity() {
				go func(a store.Alert, aid int64) {
					a.ID = aid
					if err := e.mailer.SendAlert(a); err != nil {
						e.logger.Warn("detection: email failed", "sig", sig.ID, "err", err)
					}
				}(alert, id)
			}
		}
	}
	if created > 0 {
		e.logger.Info("detection engine: threat alerts created", "count", created)
	}
}

func strOrDash(s *string) string {
	if s == nil || *s == "" { return "—" }
	return *s
}
