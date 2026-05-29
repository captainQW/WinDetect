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
					Detail: "防火墙配置文件 " + name + " 处于关闭状态",
					Fix:    "在 控制面板 > Windows Defender 防火墙 中启用该配置文件",
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
			Desc: "防病毒引擎未启用", Detail: "Windows Defender 防病毒未运行",
			Fix: "启用 Windows Defender 或确认第三方杀毒软件正常工作"})
	}
	if !st.RealTime {
		findings = append(findings, models.Finding{Sev: models.SevHigh,
			Desc: "实时保护已关闭", Detail: "实时威胁防护处于关闭状态",
			Fix: "在 Windows 安全中心启用实时保护"})
	}
	if st.SigAge > 7 {
		findings = append(findings, models.Finding{Sev: models.SevMedium,
			Desc: "病毒库过期", Detail: fmt.Sprintf("病毒定义已 %d 天未更新", st.SigAge),
			Fix: "运行 Windows 更新以刷新病毒定义"})
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
				Desc: "Windows 更新服务被禁用", Detail: "wuauserv 服务启动类型为 Disabled",
				Fix: "将 Windows Update 服务设置为手动或自动启动"})
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
				Desc: "内置管理员账户已启用", Detail: "Administrator 账户处于启用状态，易成为攻击目标",
				Fix: "禁用内置 Administrator 账户或重命名并设置强密码"})
		}
		if strings.EqualFold(u.Name, "Guest") && u.Enabled {
			findings = append(findings, models.Finding{Sev: models.SevHigh,
				Desc: "来宾账户已启用", Detail: "Guest 账户处于启用状态",
				Fix: "禁用 Guest 来宾账户"})
		}
		if u.Enabled && !u.PasswordRequired {
			findings = append(findings, models.Finding{Sev: models.SevHigh,
				Desc: "账户无需密码: " + u.Name, Detail: "该账户允许空密码登录",
				Fix: "为账户 " + u.Name + " 设置强密码"})
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
				Desc: "Telnet 端口开放 (23)", Detail: "Telnet 以明文传输凭据，极易被窃听",
				Fix: "关闭 Telnet 服务，改用 SSH"})
		case 3389:
			findings = append(findings, models.Finding{Sev: models.SevMedium,
				Desc: "远程桌面端口开放 (3389)", Detail: "RDP 暴露在网络中存在被暴力破解风险",
				Fix: "限制 RDP 访问来源或启用网络级别认证(NLA)"})
		case 445:
			findings = append(findings, models.Finding{Sev: models.SevMedium,
				Desc: "SMB 端口开放 (445)", Detail: "SMB 历史上存在多个高危漏洞",
				Fix: "如非必要，限制 445 端口的外部访问"})
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
				Desc: "可疑启动项: " + it.Name, Detail: "自启动程序位于临时目录: " + truncate(it.Cmd, 80),
				Fix: "核实该启动项来源，若非必要请移除"})
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
				Desc: "用户账户控制(UAC)已禁用", Detail: "EnableLUA 为 0，提权操作不再提示",
				Fix: "在 控制面板 > 用户账户 中启用 UAC"})
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
				Desc: "存在网络共享: " + s.Name, Detail: "共享路径: " + s.Path,
				Fix: "确认该共享为必要项并已正确设置访问权限"})
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
