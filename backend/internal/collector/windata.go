package collector

import (
	"fmt"
	"strings"

	"windetect/internal/models"
	"windetect/internal/winutil"
)

// collectServices enumerates Windows services via PowerShell/CIM.
func collectServices() []models.ServiceInfo {
	script := `Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName | ConvertTo-Json -Compress`
	var raw []struct {
		Name        string `json:"Name"`
		DisplayName string `json:"DisplayName"`
		State       string `json:"State"`
		StartMode   string `json:"StartMode"`
		StartName   string `json:"StartName"`
	}
	if err := winutil.RunPSJSON(script, &raw); err != nil || len(raw) == 0 {
		// Retry assuming a single-object (non-array) response.
		var one struct {
			Name        string `json:"Name"`
			DisplayName string `json:"DisplayName"`
			State       string `json:"State"`
			StartMode   string `json:"StartMode"`
			StartName   string `json:"StartName"`
		}
		if err2 := winutil.RunPSJSON(script, &one); err2 == nil && one.Name != "" {
			raw = append(raw, one)
		}
	}
	out := make([]models.ServiceInfo, 0, len(raw))
	for _, s := range raw {
		state := "Stopped"
		if strings.EqualFold(s.State, "Running") {
			state = "Running"
		}
		out = append(out, models.ServiceInfo{
			Name:  s.Name,
			Disp:  s.DisplayName,
			State: state,
			Start: s.StartMode,
			Acct:  s.StartName,
		})
	}
	return out
}

// collectEvents pulls recent System/Application/Security log entries.
func collectEvents() []models.EventLog {
	script := `
$logs = @('System','Application')
$evts = foreach ($l in $logs) {
  Get-WinEvent -FilterHashtable @{LogName=$l; Level=1,2,3} -MaxEvents 25 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, @{N='Msg';E={ ($_.Message -split [char]10)[0] }}
}
$evts | Sort-Object TimeCreated -Descending | Select-Object -First 60 | ConvertTo-Json -Compress`
	var raw []struct {
		TimeCreated      string `json:"TimeCreated"`
		ProviderName     string `json:"ProviderName"`
		Id               int    `json:"Id"`
		LevelDisplayName string `json:"LevelDisplayName"`
		Msg              string `json:"Msg"`
	}
	_ = winutil.RunPSJSON(script, &raw)
	out := make([]models.EventLog, 0, len(raw))
	for _, e := range raw {
		ev := models.EventLog{
			Time: parsePSDate(e.TimeCreated),
			Src:  e.ProviderName,
			Msg:  truncate(e.Msg, 160),
			Lv:   mapEventLevel(e.LevelDisplayName),
			ID:   e.Id,
		}
		// Attach plain-language cause and remediation guidance.
		cause, fix, steps, cmd := eventRemedy(e.Id, e.ProviderName, ev.Lv)
		ev.Cause = cause
		ev.Fix = fix
		ev.Steps = steps
		ev.Cmd = cmd
		out = append(out, ev)
	}
	return out
}

// eventRemedy maps a Windows event (by id/source/level) to a likely cause and
// actionable remediation. It covers the most common System/Application events
// and falls back to generic guidance by severity.
func eventRemedy(id int, source, level string) (cause, fix string, steps []string, cmd string) {
	src := strings.ToLower(source)

	switch id {
	case 41: // Kernel-Power: unexpected shutdown
		return "系统未正常关机即重启，通常由断电、电源故障、过热或硬件/驱动崩溃引起。",
			"排查供电与散热，更新芯片组/显卡驱动",
			[]string{
				"确认电源线、电池状态稳定，排除意外断电。",
				"清理机箱灰尘，检查 CPU/GPU 温度是否过高。",
				"将主板芯片组、显卡驱动更新到最新版本。",
				"运行下方命令检查是否伴随蓝屏(BugCheck 1001)记录。",
			},
			"Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -MaxEvents 5"
	case 1001: // BugCheck (BSOD) / Windows Error Reporting
		if strings.Contains(src, "bugcheck") {
			return "记录了一次蓝屏(BSOD)崩溃，多由驱动程序错误或硬件故障导致。",
				"分析转储文件定位故障驱动",
				[]string{
					"用 WinDbg 或 BlueScreenView 打开 C:\\Windows\\Minidump 下的 .dmp 文件。",
					"查看崩溃模块名，定位对应驱动并更新或回滚。",
					"运行内存诊断排除内存条故障。",
					"运行下方命令检查系统文件完整性。",
				},
				"sfc /scannow"
		}
	case 6008: // unexpected shutdown
		return "上次系统关机是意外的(非正常关机)。",
			"检查断电、强制关机或系统崩溃原因",
			[]string{
				"确认是否人为长按电源键或意外断电。",
				"检查同时间段是否有 Kernel-Power(41) 或蓝屏(1001)记录。",
				"如频繁出现，排查电源、内存与散热。",
			},
			""
	case 7000, 7011, 7034: // service failed to start / hang / crash
		return "某个 Windows 服务启动失败、超时或意外终止。",
			"检查该服务的依赖项与登录账户",
			[]string{
				"按 Win+R 输入 services.msc，找到事件中提到的服务。",
				"确认其\"依赖服务\"均已启动，登录账户与权限正确。",
				"查看服务对应程序文件是否存在或被杀软拦截。",
				"运行下方命令查看最近的服务控制管理器错误。",
			},
			"Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; Level=2} -MaxEvents 10"
	case 7045: // new service installed
		return "系统中安装了一个新服务，可能是正常软件，也可能是恶意持久化。",
			"核实新服务来源是否可信",
			[]string{
				"确认该服务对应的软件是你近期主动安装的。",
				"若来源不明，记录其可执行路径并用 VirusTotal 核实。",
				"确认为恶意后停止并删除该服务，并执行全盘查杀。",
			},
			""
	case 51, 153: // disk paging error / IO retry
		return "磁盘在读写时发生错误或重试，可能是磁盘即将损坏或连接不稳定。",
			"检查磁盘健康并备份数据",
			[]string{
				"立即备份重要数据。",
				"运行下方命令对系统盘做磁盘检查(下次重启时执行)。",
				"检查 SATA/电源数据线连接，必要时更换磁盘。",
				"在本工具\"磁盘分析\"页查看 S.M.A.R.T. 健康状态。",
			},
			"chkdsk C: /scan"
	case 1000: // application crash
		return "某个应用程序崩溃退出(Application Error)。",
			"更新或修复崩溃的应用程序",
			[]string{
				"将崩溃的程序更新到最新版本。",
				"通过\"设置 > 应用\"对其执行\"修复\"或重新安装。",
				"更新 .NET、VC++ 运行库等依赖组件。",
				"运行下方命令修复系统组件存储。",
			},
			"DISM /Online /Cleanup-Image /RestoreHealth"
	case 1002: // application hang
		return "某个应用程序无响应被强制关闭(Application Hang)。",
			"检查该程序的资源占用与冲突",
			[]string{
				"确认系统内存/CPU 是否在该时段被占满。",
				"更新该程序及其插件，关闭可能冲突的后台软件。",
				"如为浏览器或办公软件，清理缓存或重置配置。",
			},
			""
	case 11: // disk controller error (often Disk source)
		if strings.Contains(src, "disk") {
			return "磁盘控制器报告错误，通常指向磁盘或线缆问题。",
				"检查磁盘连接与健康状态",
				[]string{
					"备份重要数据以防磁盘失效。",
					"检查并重新插拔磁盘数据线/电源线。",
					"运行下方命令检查物理磁盘健康。",
				},
				"Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus,OperationalStatus"
		}
	}

	// Source-based heuristics when the id isn't specifically known.
	switch {
	case strings.Contains(src, "disk") || strings.Contains(src, "ntfs") || strings.Contains(src, "volsnap"):
		return "存储子系统报告了问题(磁盘/文件系统)。",
			"检查磁盘健康并运行文件系统检查",
			[]string{
				"备份重要数据。",
				"运行 chkdsk 检查文件系统。",
				"在\"磁盘分析\"页核对 S.M.A.R.T. 状态。",
			},
			"chkdsk C: /scan"
	case strings.Contains(src, "dcom") || strings.Contains(src, "distributedcom"):
		return "DCOM 组件权限或激活配置异常，多数情况影响有限。",
			"如频繁出现可在组件服务中修正权限",
			[]string{
				"记录事件中的 CLSID/APPID。",
				"在 dcomcnfg(组件服务)中定位对应组件并修正启动/激活权限。",
				"偶发的此类事件通常可忽略。",
			},
			""
	}

	// Generic fallback by severity.
	switch level {
	case "critical", "error":
		return "系统或应用记录了一条错误事件。",
			"根据来源与消息进一步排查",
			[]string{
				"记录事件来源(" + source + ")与事件 ID。",
				"在事件查看器中双击该事件查看完整描述与\"事件日志联机帮助\"。",
				"按描述更新相关驱动/软件或修复系统文件(sfc /scannow)。",
			},
			""
	default:
		return "", "", nil, ""
	}
}

func mapEventLevel(l string) string {
	switch strings.ToLower(l) {
	case "critical":
		return models.SevCritical
	case "error":
		return "error"
	case "warning":
		return models.SevMedium
	default:
		return "info"
	}
}

// collectAdapters enumerates network adapters and merges live throughput.
func collectAdapters(d models.DiagData) []models.NetAdapter {
	script := `Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object {
  $ip = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
  [pscustomobject]@{ Name=$_.Name; Type=$_.MediaType; Mac=$_.MacAddress; Speed=$_.LinkSpeed; Ip=$ip }
} | ConvertTo-Json -Compress`
	var raw []struct {
		Name  string `json:"Name"`
		Type  string `json:"Type"`
		Mac   string `json:"Mac"`
		Speed string `json:"Speed"`
		Ip    string `json:"Ip"`
	}
	if err := winutil.RunPSJSON(script, &raw); err != nil || len(raw) == 0 {
		var one struct {
			Name  string `json:"Name"`
			Type  string `json:"Type"`
			Mac   string `json:"Mac"`
			Speed string `json:"Speed"`
			Ip    string `json:"Ip"`
		}
		if err2 := winutil.RunPSJSON(script, &one); err2 == nil && one.Name != "" {
			raw = append(raw, one)
		}
	}
	out := make([]models.NetAdapter, 0, len(raw))
	for i, a := range raw {
		ad := models.NetAdapter{
			Name:  a.Name,
			Type:  a.Type,
			IP:    a.Ip,
			MAC:   a.Mac,
			Speed: a.Speed,
		}
		// Attribute aggregate throughput to the first (primary) adapter.
		if i == 0 {
			ad.UpKbps = d.NetUp
			ad.DnKbps = d.NetDn
		}
		out = append(out, ad)
	}
	return out
}

// hardwareWMI augments hardware info with BIOS, motherboard and GPU details.
func hardwareWMI() []models.HWSection {
	secs := []models.HWSection{}

	var bios struct {
		Manufacturer string `json:"Manufacturer"`
		Version      string `json:"SMBIOSBIOSVersion"`
		SerialNumber string `json:"SerialNumber"`
	}
	if err := winutil.RunPSJSON(`Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,SerialNumber | ConvertTo-Json -Compress`, &bios); err == nil && bios.Manufacturer != "" {
		secs = append(secs, models.HWSection{
			Icon: "🔌", Title: "BIOS",
			KV: []models.KV{
				{K: "厂商", V: bios.Manufacturer},
				{K: "版本", V: bios.Version},
				{K: "序列号", V: bios.SerialNumber},
			},
		})
	}

	var gpus []struct {
		Name      string `json:"Name"`
		DriverVer string `json:"DriverVersion"`
		RAM       int64  `json:"AdapterRAM"`
	}
	if err := winutil.RunPSJSON(`Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,AdapterRAM | ConvertTo-Json -Compress`, &gpus); err == nil {
		for _, g := range gpus {
			if g.Name == "" {
				continue
			}
			secs = append(secs, models.HWSection{
				Icon: "🎮", Title: "显卡",
				KV: []models.KV{
					{K: "型号", V: g.Name},
					{K: "驱动版本", V: g.DriverVer},
					{K: "显存", V: fmt.Sprintf("%.0f MB", float64(g.RAM)/1024/1024)},
				},
			})
		}
	}

	return secs
}

// collectRuntimes reports detected language/runtime versions.
func collectRuntimes() []models.KV {
	out := []models.KV{}
	add := func(label, script string) {
		if v, err := winutil.RunPS(script); err == nil && v != "" {
			out = append(out, models.KV{K: label, V: truncate(strings.Split(v, "\n")[0], 60)})
		} else {
			out = append(out, models.KV{K: label, V: "未安装"})
		}
	}
	add(".NET Framework", `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Version`)
	add("PowerShell", `$PSVersionTable.PSVersion.ToString()`)
	add("Node.js", `node --version 2>$null`)
	add("Python", `python --version 2>&1`)
	add("Java", `java -version 2>&1 | Select-Object -First 1`)
	add("Go", `go version 2>$null`)
	return out
}

// collectSecUpdates reports security posture key/values.
func collectSecUpdates() []models.KV {
	out := []models.KV{}

	var defender struct {
		AMEnabled       bool   `json:"AntivirusEnabled"`
		RealTime        bool   `json:"RealTimeProtectionEnabled"`
		AMVersion       string `json:"AMEngineVersion"`
		SignatureUpdated string `json:"AntivirusSignatureLastUpdated"`
	}
	if err := winutil.RunPSJSON(`Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AMEngineVersion,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress`, &defender); err == nil {
		out = append(out,
			models.KV{K: "Defender 防病毒", V: boolZh(defender.AMEnabled)},
			models.KV{K: "实时保护", V: boolZh(defender.RealTime)},
			models.KV{K: "引擎版本", V: defender.AMVersion},
		)
	}

	if v, err := winutil.RunPS(`(Get-Date).ToString('yyyy-MM-dd')`); err == nil {
		out = append(out, models.KV{K: "检测日期", V: v})
	}
	return out
}

// collectPatches lists recently installed hotfixes (proxy for update state).
func collectPatches() []models.Patch {
	script := `Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID,Description,InstalledOn | ConvertTo-Json -Compress`
	var raw []struct {
		HotFixID    string `json:"HotFixID"`
		Description string `json:"Description"`
		InstalledOn string `json:"InstalledOn"`
	}
	_ = winutil.RunPSJSON(script, &raw)
	out := make([]models.Patch, 0, len(raw))
	for _, p := range raw {
		out = append(out, models.Patch{
			KB:   p.HotFixID,
			Desc: p.Description,
			Type: "已安装更新",
			Date: parsePSDate(p.InstalledOn),
			Sev:  "信息",
		})
	}
	return out
}

func boolZh(b bool) string {
	if b {
		return "已启用"
	}
	return "已禁用"
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// parsePSDate normalises various PowerShell date string formats.
func parsePSDate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// PowerShell ConvertTo-Json emits "/Date(ms)/" for DateTime values.
	if strings.HasPrefix(s, "/Date(") {
		inner := strings.TrimSuffix(strings.TrimPrefix(s, "/Date("), ")/")
		// Strip timezone offset if present.
		if idx := strings.IndexAny(inner, "+-"); idx > 0 {
			inner = inner[:idx]
		}
		var ms int64
		fmt.Sscanf(inner, "%d", &ms)
		if ms > 0 {
			return msToDate(ms)
		}
	}
	return s
}
