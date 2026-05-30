package collector

import (
	"fmt"
	"strings"

	"windetect/internal/models"
	"windetect/internal/winutil"
)

// scanFirewall checks that all three firewall profiles are enabled.
func scanFirewall() ([]models.Finding, []map[string]string) {
	script := `Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress`
	findings := []models.Finding{}
	data := []map[string]string{}

	// Enabled may serialize as bool true/false; handle both via a flexible decode.
	var flex []map[string]interface{}
	if err := winutil.RunPSJSON(script, &flex); err == nil {
		for _, p := range flex {
			name := fmt.Sprintf("%v", p["Name"])
			enabled := truthy(p["Enabled"])
			data = append(data, map[string]string{
				"配置项": "防火墙配置 (" + name + ")",
				"状态":  boolZh(enabled),
			})
			if !enabled {
				findings = append(findings, models.Finding{
					Sev:    models.SevHigh,
					Desc:   name + " 防火墙未启用",
					Detail: "防火墙配置文件 " + name + " 处于关闭状态，系统更易受到来自网络的扫描和入侵。",
					Fix:    "启用 " + name + " 配置文件的 Windows 防火墙",
					Steps: []string{
						"按 Win+R 输入 wf.msc 打开\"高级安全 Windows Defender 防火墙\"。",
						"点击左侧\"Windows Defender 防火墙属性\"，切换到\"" + name + "配置文件\"选项卡。",
						"将\"防火墙状态\"设置为\"启用(推荐)\"，入站连接设为\"阻止(默认)\"。",
						"点击\"确定\"保存；或直接以管理员身份运行下方命令。",
						"如防火墙被组策略锁定，需联系域管理员或检查本地组策略 (gpedit.msc)。",
					},
					Cmd: "Set-NetFirewallProfile -Name " + name + " -Enabled True",
					Ref: "若使用第三方安全软件接管防火墙，请确认其防护已开启。",
				})
			}
		}
	}
	if len(data) == 0 {
		data = append(data, map[string]string{"配置项": "防火墙状态", "状态": "无法读取"})
	}
	return findings, data
}

// scanDefender checks antivirus state and signature freshness.
func scanDefender() ([]models.Finding, []map[string]string) {
	var st struct {
		AMEnabled        bool   `json:"AntivirusEnabled"`
		RealTime         bool   `json:"RealTimeProtectionEnabled"`
		AMVersion        string `json:"AMEngineVersion"`
		SigAge           int    `json:"AntivirusSignatureAge"`
		TamperProtection bool   `json:"IsTamperProtected"`
	}
	findings := []models.Finding{}
	data := []map[string]string{}

	err := winutil.RunPSJSON(`Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AMEngineVersion,AntivirusSignatureAge,IsTamperProtected | ConvertTo-Json -Compress`, &st)
	if err != nil {
		return []models.Finding{}, []map[string]string{{"配置项": "Defender", "状态": "无法读取(可能由第三方杀软接管)"}}
	}

	data = append(data,
		map[string]string{"配置项": "防病毒引擎", "状态": boolZh(st.AMEnabled)},
		map[string]string{"配置项": "实时保护", "状态": boolZh(st.RealTime)},
		map[string]string{"配置项": "引擎版本", "状态": st.AMVersion},
		map[string]string{"配置项": "病毒库存龄", "状态": fmt.Sprintf("%d 天", st.SigAge)},
		map[string]string{"配置项": "篡改防护", "状态": boolZh(st.TamperProtection)},
	)

	if !st.AMEnabled {
		findings = append(findings, models.Finding{Sev: models.SevCritical,
			Desc: "防病毒引擎未启用", Detail: "Windows Defender 防病毒未运行，系统缺乏恶意软件防护。",
			Fix: "启用 Windows Defender 或确认第三方杀软正常工作",
			Steps: []string{
				"打开\"Windows 安全中心\" > \"病毒和威胁防护\"。",
				"若提示由第三方杀软接管，确认该软件已激活且病毒库为最新。",
				"若无第三方杀软，运行下方命令重新启用 Defender 实时监控。",
				"重启后再次执行 Get-MpComputerStatus 确认 AntivirusEnabled 为 True。",
			},
			Cmd: "Set-MpPreference -DisableRealtimeMonitoring $false",
			Ref: "企业环境中该项可能被组策略 (Microsoft Defender Antivirus) 控制。",
		})
	}
	if !st.RealTime {
		findings = append(findings, models.Finding{Sev: models.SevHigh,
			Desc: "实时保护已关闭", Detail: "实时威胁防护处于关闭状态，新下载的文件不会被即时扫描。",
			Fix: "在 Windows 安全中心启用实时保护",
			Steps: []string{
				"打开\"Windows 安全中心\" > \"病毒和威胁防护\" > \"管理设置\"。",
				"将\"实时保护\"开关打开。",
				"若开关变灰无法操作，多为篡改防护或组策略锁定，需先关闭篡改防护或调整策略。",
				"或以管理员身份运行下方命令。",
			},
			Cmd: "Set-MpPreference -DisableRealtimeMonitoring $false",
		})
	}
	if st.SigAge > 7 {
		findings = append(findings, models.Finding{Sev: models.SevMedium,
			Desc: "病毒库过期", Detail: fmt.Sprintf("病毒定义已 %d 天未更新，对最新威胁的识别能力下降。", st.SigAge),
			Fix: "立即更新病毒定义",
			Steps: []string{
				"确认网络连接正常。",
				"运行下方命令强制更新病毒签名。",
				"或打开\"Windows 安全中心\" > \"病毒和威胁防护\" > \"检查更新\"。",
				"确认 Windows Update 服务 (wuauserv) 未被禁用。",
			},
			Cmd: "Update-MpSignature",
		})
	}
	if st.AMEnabled && !st.TamperProtection {
		findings = append(findings, models.Finding{Sev: models.SevLow,
			Desc: "篡改防护未开启", Detail: "篡改防护可阻止恶意软件关闭 Defender 的安全设置。",
			Fix: "在安全中心启用篡改防护",
			Steps: []string{
				"打开\"Windows 安全中心\" > \"病毒和威胁防护\" > \"管理设置\"。",
				"将\"篡改防护\"开关打开。",
			},
		})
	}
	return findings, data
}

// scanUpdate flags when the last update install is stale.
func scanUpdate() ([]models.Finding, []map[string]string) {
	script := `Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID,InstalledOn | ConvertTo-Json -Compress`
	var last struct {
		HotFixID    string `json:"HotFixID"`
		InstalledOn string `json:"InstalledOn"`
	}
	findings := []models.Finding{}
	data := []map[string]string{}
	_ = winutil.RunPSJSON(script, &last)

	if last.HotFixID != "" {
		data = append(data,
			map[string]string{"配置项": "最近更新", "状态": last.HotFixID},
			map[string]string{"配置项": "安装日期", "状态": parsePSDate(last.InstalledOn)},
		)
	}

	// Windows Update service should be enabled (not disabled).
	var wuStart string
	if v, err := winutil.RunPS(`(Get-Service wuauserv).StartType`); err == nil {
		wuStart = strings.TrimSpace(v)
		data = append(data, map[string]string{"配置项": "更新服务启动类型", "状态": wuStart})
		if strings.EqualFold(wuStart, "Disabled") {
			findings = append(findings, models.Finding{Sev: models.SevHigh,
				Desc: "Windows 更新服务被禁用", Detail: "wuauserv 服务启动类型为 Disabled，系统将无法获取安全补丁。",
				Fix: "将 Windows Update 服务恢复为手动/自动启动",
				Steps: []string{
					"按 Win+R 输入 services.msc 打开服务管理器。",
					"找到\"Windows Update\"服务，双击打开属性。",
					"将\"启动类型\"改为\"手动\"或\"自动(延迟启动)\"，点击\"启动\"。",
					"或以管理员身份运行下方命令后重新检查更新。",
				},
				Cmd: "Set-Service wuauserv -StartupType Manual; Start-Service wuauserv",
			})
		}
	}
	if len(data) == 0 {
		data = append(data, map[string]string{"配置项": "更新状态", "状态": "无法读取"})
	}
	return findings, data
}

// scanAccounts checks for enabled built-in accounts and weak password policy.
func scanAccounts() ([]models.Finding, []map[string]string) {
	script := `Get-LocalUser | Select-Object Name,Enabled,PasswordRequired | ConvertTo-Json -Compress`
	var users []struct {
		Name             string `json:"Name"`
		Enabled          bool   `json:"Enabled"`
		PasswordRequired bool   `json:"PasswordRequired"`
	}
	findings := []models.Finding{}
	data := []map[string]string{}
	_ = winutil.RunPSJSON(script, &users)

	for _, u := range users {
		data = append(data, map[string]string{
			"用户":   u.Name,
			"启用":   boolZh(u.Enabled),
			"需要密码": boolZh(u.PasswordRequired),
		})
		if strings.EqualFold(u.Name, "Administrator") && u.Enabled {
			findings = append(findings, models.Finding{Sev: models.SevMedium,
				Desc: "内置管理员账户已启用", Detail: "Administrator 账户名称固定，是暴力破解和提权攻击的常见目标。",
				Fix: "禁用内置 Administrator 账户，改用普通管理员账户",
				Steps: []string{
					"确认当前使用的是另一个具备管理员权限的账户(避免锁死)。",
					"按 Win+R 输入 lusrmgr.msc，进入\"用户\"，右键 Administrator > 属性。",
					"勾选\"账户已禁用\"并确定；或运行下方命令。",
					"如确需保留，请将其重命名并设置 14 位以上强密码。",
				},
				Cmd: "Disable-LocalUser -Name Administrator",
			})
		}
		if strings.EqualFold(u.Name, "Guest") && u.Enabled {
			findings = append(findings, models.Finding{Sev: models.SevHigh,
				Desc: "来宾账户已启用", Detail: "Guest 账户允许匿名访问，存在数据泄露和横向移动风险。",
				Fix: "立即禁用 Guest 来宾账户",
				Steps: []string{
					"按 Win+R 输入 lusrmgr.msc，进入\"用户\"。",
					"右键 Guest > 属性，勾选\"账户已禁用\"。",
					"或以管理员身份运行下方命令。",
				},
				Cmd: "Disable-LocalUser -Name Guest",
			})
		}
		if u.Enabled && !u.PasswordRequired {
			findings = append(findings, models.Finding{Sev: models.SevHigh,
				Desc: "账户无需密码: " + u.Name, Detail: "账户 " + u.Name + " 允许空密码登录，任何人可直接使用该账户。",
				Fix: "为账户 " + u.Name + " 设置强密码并强制要求密码",
				Steps: []string{
					"运行下方命令为该账户设置强密码(交互式输入)。",
					"在\"本地安全策略\" (secpol.msc) > 账户策略 > 密码策略 中，启用\"密码必须符合复杂性要求\"。",
					"将\"密码长度最小值\"设为 8 位以上，建议 14 位。",
				},
				Cmd: "net user " + u.Name + " *",
			})
		}
	}
	if len(data) == 0 {
		data = append(data, map[string]string{"用户": "—", "启用": "无法读取", "需要密码": "—"})
	}
	return findings, data
}

// scanNetwork inspects listening ports for risky exposed services.
func scanNetwork() ([]models.Finding, []map[string]string) {
	script := `Get-NetTCPConnection -State Listen | Select-Object -Unique LocalPort | Sort-Object LocalPort | ConvertTo-Json -Compress`
	var ports []struct {
		LocalPort int `json:"LocalPort"`
	}
	findings := []models.Finding{}
	data := []map[string]string{}
	_ = winutil.RunPSJSON(script, &ports)

	risky := map[int]string{
		23:   "Telnet (明文传输)",
		21:   "FTP (明文传输)",
		135:  "RPC 端口",
		445:  "SMB 文件共享",
		3389: "远程桌面 RDP",
		5900: "VNC 远程控制",
	}
	for _, p := range ports {
		label := "监听端口"
		if r, ok := risky[p.LocalPort]; ok {
			label = r
		}
		data = append(data, map[string]string{
			"端口": fmt.Sprintf("%d", p.LocalPort),
			"说明": label,
		})
		switch p.LocalPort {
		case 23:
			findings = append(findings, models.Finding{Sev: models.SevCritical,
				Desc: "Telnet 端口开放 (23)", Detail: "Telnet 以明文传输账号密码，极易被网络嗅探窃取凭据。",
				Fix: "关闭 Telnet 服务，改用 SSH 等加密协议",
				Steps: []string{
					"运行下方命令卸载 Telnet 服务端功能。",
					"如需远程命令行，改用 OpenSSH 服务端 (Add-WindowsCapability)。",
					"在防火墙中阻止 23 端口的入站连接。",
				},
				Cmd: "Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer",
			})
		case 21:
			findings = append(findings, models.Finding{Sev: models.SevHigh,
				Desc: "FTP 端口开放 (21)", Detail: "标准 FTP 明文传输数据与凭据，存在被窃听风险。",
				Fix: "停用明文 FTP，改用 SFTP/FTPS",
				Steps: []string{
					"如非必要，在 IIS 管理器或服务中停止并禁用 FTP 服务。",
					"确需文件传输时改用 SFTP(基于 SSH)或 FTPS(基于 TLS)。",
					"在防火墙中限制 21 端口仅对可信来源开放。",
				},
				Cmd: "Stop-Service ftpsvc; Set-Service ftpsvc -StartupType Disabled",
			})
		case 3389:
			findings = append(findings, models.Finding{Sev: models.SevMedium,
				Desc: "远程桌面端口开放 (3389)", Detail: "RDP 暴露在网络中存在被暴力破解和漏洞利用的风险。",
				Fix: "启用网络级认证(NLA)并限制访问来源",
				Steps: []string{
					"在\"系统属性\" > \"远程\"中勾选\"仅允许运行使用网络级别身份验证的远程桌面的计算机连接\"。",
					"通过防火墙规则将 3389 仅开放给可信 IP 段，或改用 VPN 接入。",
					"考虑修改默认端口并启用账户锁定策略以防暴力破解。",
					"非必要时运行下方命令关闭远程桌面。",
				},
				Cmd: "Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1",
			})
		case 445:
			findings = append(findings, models.Finding{Sev: models.SevMedium,
				Desc: "SMB 端口开放 (445)", Detail: "SMB 历史上存在 EternalBlue 等高危漏洞，暴露于公网风险极高。",
				Fix: "限制 445 端口外部访问并禁用 SMBv1",
				Steps: []string{
					"运行下方命令禁用已废弃且不安全的 SMBv1 协议。",
					"在防火墙中阻止来自外网的 445/139 入站连接。",
					"确认系统已安装最新的 SMB 相关安全补丁。",
				},
				Cmd: "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
			})
		}
	}
	if len(data) == 0 {
		data = append(data, map[string]string{"端口": "—", "说明": "无监听端口或无法读取"})
	}
	return findings, data
}

// scanStartup enumerates auto-start programs from the registry Run keys.
func scanStartup() ([]models.Finding, []map[string]string) {
	script := `
$paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')
$items = foreach ($p in $paths) {
  $k = Get-Item $p -ErrorAction SilentlyContinue
  if ($k) { $k.GetValueNames() | ForEach-Object { [pscustomobject]@{ Name=$_; Cmd=$k.GetValue($_); Hive=$p } } }
}
$items | ConvertTo-Json -Compress`
	var items []struct {
		Name string `json:"Name"`
		Cmd  string `json:"Cmd"`
		Hive string `json:"Hive"`
	}
	findings := []models.Finding{}
	data := []map[string]string{}
	_ = winutil.RunPSJSON(script, &items)

	for _, it := range items {
		data = append(data, map[string]string{
			"名称": it.Name,
			"命令": truncate(it.Cmd, 80),
		})
		lc := strings.ToLower(it.Cmd)
		if strings.Contains(lc, "\\temp\\") || strings.Contains(lc, "\\appdata\\local\\temp") {
			findings = append(findings, models.Finding{Sev: models.SevHigh,
				Desc: "可疑启动项: " + it.Name, Detail: "自启动程序位于临时目录，正常软件极少这样部署，疑似恶意程序: " + truncate(it.Cmd, 80),
				Fix: "核实来源后移除该启动项并全盘查杀",
				Steps: []string{
					"用任务管理器\"启动\"选项卡或 Autoruns 工具定位该项。",
					"将可执行文件上传 VirusTotal 核实是否为恶意程序。",
					"确认为恶意后，运行下方命令删除注册表自启动项。",
					"使用 Windows Defender 执行一次完整扫描。",
				},
				Cmd: "Remove-ItemProperty -Path '" + it.Hive + "' -Name '" + it.Name + "'",
			})
		}
	}
	if len(data) == 0 {
		data = append(data, map[string]string{"名称": "—", "命令": "无自启动项或无法读取"})
	}
	return findings, data
}

// scanUAC verifies User Account Control is enabled.
func scanUAC() ([]models.Finding, []map[string]string) {
	findings := []models.Finding{}
	data := []map[string]string{}

	enabledVal, err := winutil.RunPS(`(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA`)
	if err == nil {
		on := strings.TrimSpace(enabledVal) == "1"
		data = append(data, map[string]string{"配置项": "UAC (EnableLUA)", "状态": boolZh(on)})
		if !on {
			findings = append(findings, models.Finding{Sev: models.SevHigh,
				Desc: "用户账户控制(UAC)已禁用", Detail: "EnableLUA 为 0，程序可在用户无感知下获得管理员权限。",
				Fix: "重新启用 UAC 并设置为始终提示",
				Steps: []string{
					"运行下方命令将 EnableLUA 置为 1。",
					"或在控制面板搜索\"UAC\"，将滑块调到\"始终通知\"。",
					"修改后需重启计算机才能生效。",
				},
				Cmd: "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1",
				Ref: "修改后务必重启系统。",
			})
		}
	}

	if v, err := winutil.RunPS(`(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').ConsentPromptBehaviorAdmin`); err == nil {
		data = append(data, map[string]string{"配置项": "管理员提权提示级别", "状态": strings.TrimSpace(v)})
	}
	if len(data) == 0 {
		data = append(data, map[string]string{"配置项": "UAC", "状态": "无法读取"})
	}
	return findings, data
}

// scanShares lists non-administrative network shares.
func scanShares() ([]models.Finding, []map[string]string) {
	script := `Get-SmbShare | Select-Object Name,Path,Description | ConvertTo-Json -Compress`
	var shares []struct {
		Name        string `json:"Name"`
		Path        string `json:"Path"`
		Description string `json:"Description"`
	}
	findings := []models.Finding{}
	data := []map[string]string{}
	_ = winutil.RunPSJSON(script, &shares)

	for _, s := range shares {
		data = append(data, map[string]string{
			"共享名": s.Name,
			"路径":  s.Path,
		})
		// Administrative shares end with $; user-created shares warrant review.
		if !strings.HasSuffix(s.Name, "$") {
			findings = append(findings, models.Finding{Sev: models.SevLow,
				Desc: "存在网络共享: " + s.Name, Detail: "共享 " + s.Name + " 指向 " + s.Path + "，若权限配置不当可能泄露文件。",
				Fix: "确认共享必要性并收紧访问权限",
				Steps: []string{
					"运行 Get-SmbShareAccess -Name '" + s.Name + "' 查看当前授权账户。",
					"移除\"Everyone\"等过宽权限，仅授权必要用户/组。",
					"如不再需要该共享，运行下方命令移除。",
				},
				Cmd: "Remove-SmbShare -Name '" + s.Name + "' -Force",
			})
		}
	}
	if len(data) == 0 {
		data = append(data, map[string]string{"共享名": "—", "路径": "无共享或无法读取"})
	}
	return findings, data
}

// truthy interprets PowerShell bool/int JSON values.
func truthy(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t != 0
	case string:
		return t == "1" || strings.EqualFold(t, "true")
	}
	return false
}
