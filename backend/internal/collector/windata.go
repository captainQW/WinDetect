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
    Select-Object TimeCreated, ProviderName, LevelDisplayName, @{N='Msg';E={ ($_.Message -split [char]10)[0] }}
}
$evts | Sort-Object TimeCreated -Descending | Select-Object -First 60 | ConvertTo-Json -Compress`
	var raw []struct {
		TimeCreated      string `json:"TimeCreated"`
		ProviderName     string `json:"ProviderName"`
		LevelDisplayName string `json:"LevelDisplayName"`
		Msg              string `json:"Msg"`
	}
	_ = winutil.RunPSJSON(script, &raw)
	out := make([]models.EventLog, 0, len(raw))
	for _, e := range raw {
		out = append(out, models.EventLog{
			Time: parsePSDate(e.TimeCreated),
			Src:  e.ProviderName,
			Msg:  truncate(e.Msg, 160),
			Lv:   mapEventLevel(e.LevelDisplayName),
		})
	}
	return out
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
