package collector

import (
	"sort"

	"windetect/internal/models"
	"windetect/internal/winutil"
)

// reliabilityWindowDays is the look-back period for the stability analysis,
// matching the rolling window Windows Reliability Monitor uses.
const reliabilityWindowDays = 14

// collectReliability builds a Reliability Monitor-style stability summary by
// counting crashes, hangs, bugchecks, service failures and unexpected
// shutdowns in the recent event logs, then derives a 1-10 stability index.
func collectReliability() models.ReliabilityResult {
	res := models.ReliabilityResult{WindowDays: reliabilityWindowDays}

	// Pull the stability-relevant events in one pass. Each row is classified
	// by (LogName, ProviderName, Id) into a reliability category.
	script := `$ErrorActionPreference='SilentlyContinue'
$since = (Get-Date).AddDays(-14)
$rows = @()
$rows += Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Application Error'; StartTime=$since} -MaxEvents 40 -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); Cat='crash'; Src=(($_.Message -split [char]10)[0]) } }
$rows += Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Application Hang'; StartTime=$since} -MaxEvents 40 -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); Cat='hang'; Src=(($_.Message -split [char]10)[0]) } }
$rows += Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'; StartTime=$since} -MaxEvents 40 -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); Cat='bsod'; Src=(($_.Message -split [char]10)[0]) } }
$rows += Get-WinEvent -FilterHashtable @{LogName='System'; Id=41; StartTime=$since} -MaxEvents 40 -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); Cat='shutdown'; Src='Kernel-Power: 系统未正常关机即重启' } }
$rows += Get-WinEvent -FilterHashtable @{LogName='System'; Id=6008; StartTime=$since} -MaxEvents 40 -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); Cat='shutdown'; Src='上次关机为意外关机' } }
$rows += Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; Id=7034; StartTime=$since} -MaxEvents 40 -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); Cat='svc'; Src=(($_.Message -split [char]10)[0]) } }
$rows | ConvertTo-Json -Compress`

	var raw []struct {
		Time string `json:"Time"`
		Cat  string `json:"Cat"`
		Src  string `json:"Src"`
	}
	if err := winutil.RunPSJSON(script, &raw); err != nil || len(raw) == 0 {
		// Single-row responses arrive as a bare object.
		var one struct {
			Time string `json:"Time"`
			Cat  string `json:"Cat"`
			Src  string `json:"Src"`
		}
		if err2 := winutil.RunPSJSON(script, &one); err2 == nil && one.Cat != "" {
			raw = append(raw, struct {
				Time string `json:"Time"`
				Cat  string `json:"Cat"`
				Src  string `json:"Src"`
			}(one))
		}
	}

	for _, r := range raw {
		ev := classifyReliability(r.Cat, r.Time, r.Src)
		res.Events = append(res.Events, ev)
		switch r.Cat {
		case "crash":
			res.AppCrashes++
		case "hang":
			res.AppHangs++
		case "bsod":
			res.BSODs++
		case "svc":
			res.SvcFailures++
		case "shutdown":
			res.UngracefulShutdowns++
		}
	}

	// Newest first.
	sort.SliceStable(res.Events, func(i, j int) bool {
		return res.Events[i].Time > res.Events[j].Time
	})
	if len(res.Events) > 50 {
		res.Events = res.Events[:50]
	}

	res.Index, res.Level = stabilityIndex(res)
	return res
}

func classifyReliability(cat, t, src string) models.ReliabilityEvent {
	switch cat {
	case "crash":
		return models.ReliabilityEvent{Time: t, Type: "应用崩溃", Sev: models.SevHigh, Source: "Application Error",
			Detail: src, Fix: "更新或修复该应用，修复运行库 (DISM /Online /Cleanup-Image /RestoreHealth)"}
	case "hang":
		return models.ReliabilityEvent{Time: t, Type: "应用无响应", Sev: models.SevMedium, Source: "Application Hang",
			Detail: src, Fix: "检查资源占用与软件冲突，更新该程序"}
	case "bsod":
		return models.ReliabilityEvent{Time: t, Type: "系统崩溃 (蓝屏)", Sev: models.SevCritical, Source: "WER",
			Detail: src, Fix: "分析 Minidump 定位故障驱动，运行内存诊断"}
	case "shutdown":
		return models.ReliabilityEvent{Time: t, Type: "异常关机", Sev: models.SevHigh, Source: "Kernel-Power",
			Detail: src, Fix: "排查断电/过热/电源，更新芯片组与显卡驱动"}
	case "svc":
		return models.ReliabilityEvent{Time: t, Type: "服务意外终止", Sev: models.SevMedium, Source: "Service Control Manager",
			Detail: src, Fix: "检查服务依赖与登录账户，确认程序文件未被拦截"}
	}
	return models.ReliabilityEvent{Time: t, Type: "其他", Sev: "info", Detail: src}
}

// stabilityIndex derives a 1-10 stability score (10 = perfectly stable),
// weighting severe events more heavily, similar to Reliability Monitor.
func stabilityIndex(r models.ReliabilityResult) (float64, string) {
	penalty := float64(r.BSODs)*2.5 +
		float64(r.UngracefulShutdowns)*1.5 +
		float64(r.AppCrashes)*0.8 +
		float64(r.SvcFailures)*0.6 +
		float64(r.AppHangs)*0.4

	idx := 10.0 - penalty
	if idx < 1 {
		idx = 1
	}
	idx = round1(idx)

	level := "稳定"
	switch {
	case idx < 4:
		level = "不稳定"
	case idx < 7:
		level = "一般"
	}
	return idx, level
}
