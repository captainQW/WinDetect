package collector

import (
	"fmt"
	"strings"

	"windetect/internal/models"
	"windetect/internal/winutil"
)

// hardeningState is the consolidated security-policy snapshot read in one
// PowerShell pass to keep the hardening scan fast.
type hardeningState struct {
	LockoutThreshold int    `json:"LockoutThreshold"`
	LockoutDuration  int    `json:"LockoutDuration"`
	MaxPwdAge        int    `json:"MaxPwdAge"`
	MinPwdLen        int    `json:"MinPwdLen"`
	PwdComplexity    int    `json:"PwdComplexity"`
	RDPEnabled       int    `json:"RDPEnabled"`
	RDPNla           int    `json:"RDPNla"`
	SMB1             string `json:"SMB1"`
	AutoLogon        string `json:"AutoLogon"`
	ScreenSaverTO    string `json:"ScreenSaverTO"`
	AuditLogon       string `json:"AuditLogon"`
	LLMNR            int    `json:"LLMNR"`
}

// scanHardening implements the security-baseline checks from the requirements
// doc section 9 (system/network hardening) cross-referenced with CIS
// Benchmarks for Windows. It evaluates high-risk ports, account lockout /
// password policy, session timeout, RDP NLA, SMBv1, autologon, audit policy
// and LLMNR, each mapped to a MITRE ATT&CK technique where relevant.
func scanHardening() ([]models.Finding, []map[string]string) {
	findings := []models.Finding{}
	data := []map[string]string{}

	st := readHardeningState()

	// --- 1. High-risk listening ports (135/137/138/139/445/3389) ---------
	risky := map[int]string{
		135: "RPC", 137: "NetBIOS 名称", 138: "NetBIOS 数据报",
		139: "NetBIOS 会话", 445: "SMB", 3389: "远程桌面(RDP)",
	}
	openRisky := detectRiskyPorts(risky)
	for _, p := range openRiskyOrdered(openRisky) {
		data = append(data, map[string]string{
			"检查项": fmt.Sprintf("高危端口 %d (%s)", p, risky[p]),
			"状态":  "开放",
			"基线":  "建议关闭/限制",
		})
	}
	if len(openRisky) > 0 {
		ports := openRiskyStrings(openRisky)
		findings = append(findings, models.Finding{
			Sev:  models.SevMedium,
			Desc: "开放了高危端口: " + strings.Join(ports, ", "),
			Detail: "检测到 NetBIOS/RPC/SMB/RDP 等高危端口对外监听，这些端口是横向移动与勒索软件传播的常见入口。",
			Fix:   "通过防火墙限制这些端口仅对授权 IP 开放，或关闭不需要的服务",
			Steps: []string{
				"确认哪些端口对应的服务确实需要：135/139/445 多用于文件与打印共享，3389 用于远程桌面。",
				"在 Windows Defender 防火墙中为这些端口添加入站规则，限定来源 IP 段。",
				"关闭 NetBIOS over TCP/IP（网络适配器属性 > IPv4 > 高级 > WINS）。",
				"如不使用文件共享，停用 Server 服务以关闭 445。",
			},
			Cmd:     "Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 135,137,139,445,3389 | Select-Object LocalPort,OwningProcess",
			Mitre:   "T1021",
			MitreNm: "远程服务 (横向移动)",
			CIS:     "CIS 9.x 防火墙规则",
		})
	}

	// --- 2. Account lockout policy ---------------------------------------
	data = append(data, map[string]string{
		"检查项": "账户锁定阈值",
		"状态":  lockoutZh(st.LockoutThreshold),
		"基线":  "≤ 5 次 (CIS 1.2.2)",
	})
	if st.LockoutThreshold == 0 {
		findings = append(findings, models.Finding{
			Sev:  models.SevMedium,
			Desc: "未配置账户锁定策略",
			Detail: "登录失败次数无限制，攻击者可对账户进行无限次暴力破解(密码喷洒)。",
			Fix:   "设置账户锁定阈值为 5 次以内",
			Steps: []string{
				"运行 secpol.msc 打开本地安全策略。",
				"进入 账户策略 > 账户锁定策略。",
				"将\"账户锁定阈值\"设为 5 次无效登录，锁定时间 15 分钟以上。",
				"或以管理员身份运行下方命令。",
			},
			Cmd:     "net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15",
			Mitre:   "T1110",
			MitreNm: "暴力破解",
			CIS:     "CIS 1.2.1-1.2.3",
		})
	}

	// --- 3. Password policy (length / complexity) ------------------------
	data = append(data, map[string]string{
		"检查项": "密码最小长度",
		"状态":  fmt.Sprintf("%d 位", st.MinPwdLen),
		"基线":  "≥ 14 位 (CIS 1.1.4)",
	})
	if st.MinPwdLen > 0 && st.MinPwdLen < 8 {
		findings = append(findings, models.Finding{
			Sev:  models.SevMedium,
			Desc: fmt.Sprintf("密码最小长度过短 (%d 位)", st.MinPwdLen),
			Detail: "短密码极易被暴力破解或字典攻击攻破。",
			Fix:   "将密码最小长度提升至 14 位并启用复杂性要求",
			Steps: []string{
				"运行 secpol.msc > 账户策略 > 密码策略。",
				"将\"密码长度最小值\"设为 14。",
				"启用\"密码必须符合复杂性要求\"。",
			},
			Cmd:     "net accounts /minpwlen:14",
			Mitre:   "T1110.001",
			MitreNm: "密码猜测",
			CIS:     "CIS 1.1.4-1.1.5",
		})
	}
	if st.PwdComplexity == 0 {
		findings = append(findings, models.Finding{
			Sev:  models.SevLow,
			Desc: "未启用密码复杂性要求",
			Detail: "允许使用简单密码，降低了账户安全强度。",
			Fix:   "启用密码复杂性策略",
			Steps: []string{
				"运行 secpol.msc > 账户策略 > 密码策略。",
				"启用\"密码必须符合复杂性要求\"。",
			},
			Mitre:   "T1110",
			MitreNm: "暴力破解",
			CIS:     "CIS 1.1.5",
		})
	}

	// --- 4. Session timeout / screensaver lock ---------------------------
	data = append(data, map[string]string{
		"检查项": "屏幕保护超时锁定",
		"状态":  screenTOZh(st.ScreenSaverTO),
		"基线":  "≤ 900 秒 (CIS 19.1.3)",
	})
	if !screenLockOK(st.ScreenSaverTO) {
		findings = append(findings, models.Finding{
			Sev:  models.SevLow,
			Desc: "未启用会话超时锁定",
			Detail: "无人值守时屏幕不会自动锁定，存在被他人物理访问的风险。",
			Fix:   "启用 15 分钟内自动锁定屏幕",
			Steps: []string{
				"设置 > 个性化 > 锁屏 > 屏幕保护程序设置。",
				"勾选\"在恢复时显示登录屏幕\"，等待时间设为 15 分钟以内。",
				"或组策略 gpedit.msc > 用户配置 > 管理模板 > 控制面板 > 个性化 中启用相关策略。",
			},
			Mitre:   "T1078",
			MitreNm: "有效账户 (物理访问)",
			CIS:     "CIS 19.1.3.x",
		})
	}

	// --- 5. RDP network level authentication -----------------------------
	if st.RDPEnabled == 1 {
		data = append(data, map[string]string{
			"检查项": "远程桌面网络级认证(NLA)",
			"状态":  boolZh(st.RDPNla == 1),
			"基线":  "应启用 (CIS 18.x)",
		})
		if st.RDPNla != 1 {
			findings = append(findings, models.Finding{
				Sev:  models.SevHigh,
				Desc: "远程桌面未启用网络级认证(NLA)",
				Detail: "未启用 NLA 时，攻击者无需认证即可建立 RDP 会话，增大被攻击面与漏洞利用风险。",
				Fix:   "启用 RDP 网络级别身份验证",
				Steps: []string{
					"系统属性 > 远程 > 勾选\"仅允许运行使用网络级别身份验证的远程桌面的计算机连接\"。",
					"或以管理员身份运行下方命令后重启。",
				},
				Cmd:     "Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
				Mitre:   "T1021.001",
				MitreNm: "远程桌面协议",
				CIS:     "CIS 18.10.x",
			})
		}
	}

	// --- 6. SMBv1 protocol -----------------------------------------------
	smb1On := strings.EqualFold(strings.TrimSpace(st.SMB1), "True") || st.SMB1 == "Enabled"
	data = append(data, map[string]string{
		"检查项": "SMBv1 协议",
		"状态":  boolZh(smb1On),
		"基线":  "应禁用 (CIS 18.x)",
	})
	if smb1On {
		findings = append(findings, models.Finding{
			Sev:  models.SevHigh,
			Desc: "SMBv1 协议已启用",
			Detail: "SMBv1 已被废弃且存在 EternalBlue(WannaCry) 等高危漏洞，是勒索软件传播的主要途径。",
			Fix:   "立即禁用 SMBv1 协议",
			Steps: []string{
				"以管理员身份运行下方命令禁用 SMBv1。",
				"重启计算机使更改生效。",
				"确认业务中无依赖 SMBv1 的老旧设备。",
			},
			Cmd:     "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
			Mitre:   "T1210",
			MitreNm: "利用远程服务漏洞",
			CIS:     "CIS 18.4.3",
		})
	}

	// --- 7. Auto-logon ---------------------------------------------------
	autoLogonOn := strings.TrimSpace(st.AutoLogon) == "1"
	data = append(data, map[string]string{
		"检查项": "自动登录(AutoAdminLogon)",
		"状态":  boolZh(autoLogonOn),
		"基线":  "应禁用",
	})
	if autoLogonOn {
		findings = append(findings, models.Finding{
			Sev:  models.SevHigh,
			Desc: "已启用自动登录",
			Detail: "AutoAdminLogon 开启意味着密码以明文存储于注册表，且开机即自动登录，存在严重凭据泄露风险。",
			Fix:   "关闭自动登录并清除注册表中的明文密码",
			Steps: []string{
				"运行 netplwiz，勾选\"要使用本计算机，用户必须输入用户名和密码\"。",
				"删除注册表 Winlogon 下的 DefaultPassword 值。",
				"或运行下方命令关闭自动登录。",
			},
			Cmd:     "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 0",
			Mitre:   "T1552.002",
			MitreNm: "注册表中的凭据",
			CIS:     "CIS 18.x",
		})
	}

	// --- 8. Logon auditing -----------------------------------------------
	auditOK := strings.Contains(st.AuditLogon, "Success") && strings.Contains(st.AuditLogon, "Failure")
	data = append(data, map[string]string{
		"检查项": "登录审计策略",
		"状态":  auditZh(st.AuditLogon),
		"基线":  "成功+失败 (CIS 17.x)",
	})
	if !auditOK {
		findings = append(findings, models.Finding{
			Sev:  models.SevLow,
			Desc: "登录审计未完整开启",
			Detail: "未记录登录成功/失败事件将导致入侵后无法溯源(对应需求文档审计日志保留要求)。",
			Fix:   "开启登录事件的成功与失败审计",
			Steps: []string{
				"以管理员身份运行下方命令开启登录审计。",
				"配合事件日志归档策略，保留期建议 ≥ 180 天。",
			},
			Cmd:     `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`,
			Mitre:   "T1070",
			MitreNm: "清除痕迹 (审计缺失)",
			CIS:     "CIS 17.5.x",
		})
	}

	// --- 9. LLMNR (responder/poisoning vector) ---------------------------
	data = append(data, map[string]string{
		"检查项": "LLMNR 多播名称解析",
		"状态":  llmnrZh(st.LLMNR),
		"基线":  "建议禁用",
	})
	if st.LLMNR != 0 {
		findings = append(findings, models.Finding{
			Sev:  models.SevLow,
			Desc: "LLMNR 多播名称解析未禁用",
			Detail: "LLMNR 可被 Responder 等工具用于中间人攻击窃取 NTLM 凭据哈希。",
			Fix:   "通过组策略禁用 LLMNR",
			Steps: []string{
				"运行下方命令禁用 LLMNR。",
				"或 gpedit.msc > 计算机配置 > 管理模板 > 网络 > DNS 客户端 > 关闭多播名称解析。",
			},
			Cmd:     "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null; Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0",
			Mitre:   "T1557.001",
			MitreNm: "LLMNR/NBT-NS 投毒",
			CIS:     "CIS 18.5.4.2",
		})
	}

	if len(data) == 0 {
		data = append(data, map[string]string{"检查项": "安全基线", "状态": "无法读取", "基线": "—"})
	}
	return findings, data
}

// readHardeningState gathers all policy values in a single PowerShell pass.
func readHardeningState() hardeningState {
	script := `$ErrorActionPreference='SilentlyContinue'
$na = net accounts
function NaVal($label) { ($na | Select-String $label) -replace '.*:\s*','' -replace '\s','' }
$lt = NaVal 'lockout threshold|锁定阈值'
$ld = NaVal 'lockout duration|锁定持续'
$ml = NaVal 'Minimum password length|密码长度最小值'
$ma = NaVal 'Maximum password age|密码最长使用'
$rdp = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
$nla = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication
$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
$auto = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon).AutoAdminLogon
$ssto = (Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut).ScreenSaveTimeOut
$ssact = (Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure).ScreenSaverIsSecure
$llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast).EnableMulticast
$secedit = & auditpol /get /subcategory:"Logon" /r 2>$null | ConvertFrom-Csv
$auditLogon = ($secedit | Where-Object { $_.Subcategory -eq 'Logon' }).'Inclusion Setting'
$cpx = 0
$tmp = "$env:TEMP\secpol_$PID.cfg"
secedit /export /cfg $tmp /quiet 2>$null
if (Test-Path $tmp) {
  $cfg = Get-Content $tmp
  $c = ($cfg | Select-String 'PasswordComplexity') -replace '.*=\s*',''
  if ($c) { $cpx = [int]$c.Trim() }
  Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}
function ToInt($v) { $n=0; [int]::TryParse(($v -replace '[^\d]',''), [ref]$n) | Out-Null; $n }
[pscustomobject]@{
  LockoutThreshold = ToInt $lt
  LockoutDuration  = ToInt $ld
  MaxPwdAge        = ToInt $ma
  MinPwdLen        = ToInt $ml
  PwdComplexity    = $cpx
  RDPEnabled       = if ($rdp -eq 0) { 1 } else { 0 }
  RDPNla           = [int]$nla
  SMB1             = [string]$smb1
  AutoLogon        = [string]$auto
  ScreenSaverTO    = [string]$ssto + '|' + [string]$ssact
  AuditLogon       = [string]$auditLogon
  LLMNR            = if ($llmnr -eq $null) { 1 } else { [int]$llmnr }
} | ConvertTo-Json -Compress`

	var st hardeningState
	_ = winutil.RunPSJSONTimeout(script, 40_000_000_000, &st) // 40s
	return st
}

// detectRiskyPorts returns the set of risky ports currently in LISTEN state.
func detectRiskyPorts(risky map[int]string) map[int]bool {
	script := `Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique | ConvertTo-Json -Compress`
	var ports []int
	if err := winutil.RunPSJSON(script, &ports); err != nil || len(ports) == 0 {
		var one int
		if winutil.RunPSJSON(script, &one) == nil && one > 0 {
			ports = append(ports, one)
		}
	}
	open := map[int]bool{}
	for _, p := range ports {
		if _, ok := risky[p]; ok {
			open[p] = true
		}
	}
	return open
}

func openRiskyOrdered(open map[int]bool) []int {
	order := []int{135, 137, 138, 139, 445, 3389}
	out := []int{}
	for _, p := range order {
		if open[p] {
			out = append(out, p)
		}
	}
	return out
}

func openRiskyStrings(open map[int]bool) []string {
	out := []string{}
	for _, p := range openRiskyOrdered(open) {
		out = append(out, fmt.Sprintf("%d", p))
	}
	return out
}

func lockoutZh(n int) string {
	if n == 0 {
		return "未设置 (无限制)"
	}
	return fmt.Sprintf("%d 次", n)
}

func screenLockOK(raw string) bool {
	parts := strings.SplitN(raw, "|", 2)
	if len(parts) != 2 {
		return false
	}
	to := strings.TrimSpace(parts[0])
	secure := strings.TrimSpace(parts[1])
	if to == "" || secure != "1" {
		return false
	}
	var n int
	fmt.Sscanf(to, "%d", &n)
	return n > 0 && n <= 900
}

func screenTOZh(raw string) string {
	parts := strings.SplitN(raw, "|", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		return "未启用"
	}
	if strings.TrimSpace(parts[1]) != "1" {
		return "已设置但未要求重新登录"
	}
	return parts[0] + " 秒后锁定"
}

func auditZh(s string) string {
	if s == "" {
		return "未配置"
	}
	return s
}

func llmnrZh(v int) string {
	if v == 0 {
		return "已禁用"
	}
	return "已启用"
}
