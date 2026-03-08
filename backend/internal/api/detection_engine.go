package api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"opensiem/management/internal/notify"
	"opensiem/management/internal/store"
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
	since := time.Now().Add(-2 * time.Minute)
	events, _, err := e.db.QueryEvents(ctx, store.EventFilter{Since: since, Limit: 1000})
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
