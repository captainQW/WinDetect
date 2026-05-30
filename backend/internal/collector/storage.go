package collector

import (
	"fmt"
	"strings"

	"windetect/internal/models"
	"windetect/internal/winutil"
)

// collectPhysicalDisks reports per-disk health, media type and reliability
// counters, mirroring the disk health section of perfmon /report.
func collectPhysicalDisks() []models.PhysDisk {
	// Get-PhysicalDisk exposes media/bus/health; the StorageReliabilityCounter
	// adds temperature, wear and error counts (needs admin + driver support).
	script := `$ErrorActionPreference='SilentlyContinue'
Get-PhysicalDisk | ForEach-Object {
  $rc = $_ | Get-StorageReliabilityCounter
  [pscustomobject]@{
    Name        = $_.FriendlyName
    Media       = [string]$_.MediaType
    Bus         = [string]$_.BusType
    SizeGB      = [math]::Round($_.Size/1GB,1)
    Health      = [string]$_.HealthStatus
    OpStatus    = [string]$_.OperationalStatus
    Temp        = [int]$rc.Temperature
    Wear        = [int]$rc.Wear
    ReadErrors  = [int64]$rc.ReadErrorsTotal
    WriteErrors = [int64]$rc.WriteErrorsTotal
    PowerOnHrs  = [int64]$rc.PowerOnHours
  }
} | ConvertTo-Json -Compress`

	var raw []struct {
		Name        string  `json:"Name"`
		Media       string  `json:"Media"`
		Bus         string  `json:"Bus"`
		SizeGB      float64 `json:"SizeGB"`
		Health      string  `json:"Health"`
		OpStatus    string  `json:"OpStatus"`
		Temp        int     `json:"Temp"`
		Wear        int     `json:"Wear"`
		ReadErrors  int64   `json:"ReadErrors"`
		WriteErrors int64   `json:"WriteErrors"`
		PowerOnHrs  int64   `json:"PowerOnHrs"`
	}
	if err := winutil.RunPSJSON(script, &raw); err != nil || len(raw) == 0 {
		// Single-disk machines emit a bare object rather than an array.
		var one struct {
			Name        string  `json:"Name"`
			Media       string  `json:"Media"`
			Bus         string  `json:"Bus"`
			SizeGB      float64 `json:"SizeGB"`
			Health      string  `json:"Health"`
			OpStatus    string  `json:"OpStatus"`
			Temp        int     `json:"Temp"`
			Wear        int     `json:"Wear"`
			ReadErrors  int64   `json:"ReadErrors"`
			WriteErrors int64   `json:"WriteErrors"`
			PowerOnHrs  int64   `json:"PowerOnHrs"`
		}
		if err2 := winutil.RunPSJSON(script, &one); err2 == nil && one.Name != "" {
			raw = append(raw, struct {
				Name        string  `json:"Name"`
				Media       string  `json:"Media"`
				Bus         string  `json:"Bus"`
				SizeGB      float64 `json:"SizeGB"`
				Health      string  `json:"Health"`
				OpStatus    string  `json:"OpStatus"`
				Temp        int     `json:"Temp"`
				Wear        int     `json:"Wear"`
				ReadErrors  int64   `json:"ReadErrors"`
				WriteErrors int64   `json:"WriteErrors"`
				PowerOnHrs  int64   `json:"PowerOnHrs"`
			}(one))
		}
	}

	out := make([]models.PhysDisk, 0, len(raw))
	for _, r := range raw {
		pd := models.PhysDisk{
			Name:        strings.TrimSpace(r.Name),
			Media:       mediaTypeZh(r.Media),
			Bus:         r.Bus,
			SizeGB:      r.SizeGB,
			Health:      healthZh(r.Health),
			Temp:        r.Temp,
			Wear:        r.Wear,
			ReadErrors:  r.ReadErrors,
			WriteErrors: r.WriteErrors,
			PowerOnHrs:  r.PowerOnHrs,
		}
		pd.Smart = smartSummary(r.Health, r.ReadErrors+r.WriteErrors)
		out = append(out, pd)
	}
	return out
}

// collectProblemDevices lists Device Manager entries reporting an error code,
// matching the "problem devices" warnings in a perfmon diagnostics report.
func collectProblemDevices() []models.ProblemDevice {
	script := `$ErrorActionPreference='SilentlyContinue'
Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne $null -and $_.ConfigManagerErrorCode -ne 0 } |
  Select-Object Name,PNPClass,Status,ConfigManagerErrorCode | ConvertTo-Json -Compress`
	var raw []struct {
		Name      string `json:"Name"`
		PNPClass  string `json:"PNPClass"`
		Status    string `json:"Status"`
		ErrorCode int    `json:"ConfigManagerErrorCode"`
	}
	if err := winutil.RunPSJSON(script, &raw); err != nil || len(raw) == 0 {
		var one struct {
			Name      string `json:"Name"`
			PNPClass  string `json:"PNPClass"`
			Status    string `json:"Status"`
			ErrorCode int    `json:"ConfigManagerErrorCode"`
		}
		if err2 := winutil.RunPSJSON(script, &one); err2 == nil && one.Name != "" {
			raw = append(raw, struct {
				Name      string `json:"Name"`
				PNPClass  string `json:"PNPClass"`
				Status    string `json:"Status"`
				ErrorCode int    `json:"ConfigManagerErrorCode"`
			}(one))
		}
	}

	out := make([]models.ProblemDevice, 0, len(raw))
	for _, r := range raw {
		if r.Name == "" {
			continue
		}
		out = append(out, models.ProblemDevice{
			Name:      r.Name,
			Class:     r.PNPClass,
			Status:    r.Status,
			ErrorCode: r.ErrorCode,
			Problem:   deviceErrorZh(r.ErrorCode),
		})
	}
	return out
}

func mediaTypeZh(m string) string {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "SSD", "4":
		return "固态硬盘 (SSD)"
	case "HDD", "3":
		return "机械硬盘 (HDD)"
	case "SCM", "5":
		return "存储级内存 (SCM)"
	case "", "0", "UNSPECIFIED":
		return "未知"
	}
	return m
}

func healthZh(h string) string {
	switch strings.ToLower(strings.TrimSpace(h)) {
	case "healthy", "0":
		return "正常"
	case "warning", "1":
		return "警告"
	case "unhealthy", "2":
		return "异常"
	}
	if h == "" {
		return "未知"
	}
	return h
}

func smartSummary(health string, errs int64) string {
	switch strings.ToLower(strings.TrimSpace(health)) {
	case "healthy", "0", "":
		if errs > 0 {
			return fmt.Sprintf("通过 (累计 %d 个读写错误)", errs)
		}
		return "正常"
	case "warning", "1":
		return "警告 — 建议备份数据"
	default:
		return "异常 — 磁盘可能即将失效"
	}
}

// deviceErrorZh maps the common Device Manager (CM_PROB_*) codes to a hint.
func deviceErrorZh(code int) string {
	switch code {
	case 1:
		return "设备未正确配置"
	case 3:
		return "驱动程序可能已损坏，或内存/资源不足"
	case 10:
		return "设备无法启动"
	case 12:
		return "设备找不到足够的可用资源"
	case 14:
		return "需要重启计算机才能正常工作"
	case 18:
		return "需要重新安装此设备的驱动程序"
	case 22:
		return "设备已被禁用"
	case 24:
		return "设备不存在、工作不正常或未安装全部驱动"
	case 28:
		return "未安装此设备的驱动程序"
	case 31:
		return "设备无法工作，因驱动程序无法加载所需资源"
	case 43:
		return "Windows 因报告的问题已停止此设备"
	case 45:
		return "设备当前未连接到计算机"
	}
	return fmt.Sprintf("设备管理器错误代码 %d", code)
}
