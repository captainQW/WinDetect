package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"html"
	"strings"
	"time"

	"windetect/internal/models"
)

// Meta holds report header metadata supplied by the user.
type Meta struct {
	Computer string `json:"computer"`
	OS       string `json:"os"`
	Auditor  string `json:"auditor"`
	Date     string `json:"date"`
	Summary  string `json:"summary"`
}

// Bundle is the combined data exported in a report.
type Bundle struct {
	Meta     Meta                   `json:"meta"`
	Security *models.SecurityResult `json:"security"`
	Diag     *models.DiagResult     `json:"diag"`
}

// CSV renders findings as a CSV document.
func CSV(b Bundle) (string, error) {
	var buf bytes.Buffer
	buf.WriteString("\xEF\xBB\xBF") // UTF-8 BOM so Excel reads Chinese correctly
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"类别", "时间", "级别", "模块", "描述", "详情", "解决方法", "命令"})

	if b.Security != nil {
		for _, f := range b.Security.Findings {
			fix := f.Fix
			if len(f.Steps) > 0 {
				fix = strings.Join(f.Steps, " / ")
			}
			_ = w.Write([]string{"安全", f.Time, sevName(f.Sev), f.Cat, f.Desc, f.Detail, fix, f.Cmd})
		}
	}
	if b.Diag != nil {
		for _, d := range b.Diag.Warnings {
			_ = w.Write([]string{"诊断", b.Diag.ScanTime, sevName(d.Sev), "系统诊断", d.Desc, d.Result, d.Fix, ""})
		}
		// Reliability events.
		for _, e := range b.Diag.Reliability.Events {
			_ = w.Write([]string{"可靠性", e.Time, sevName(e.Sev), e.Type, e.Source, e.Detail, e.Fix, ""})
		}
	}
	w.Flush()
	return buf.String(), w.Error()
}

// HTML renders a standalone HTML report.
func HTML(b Bundle) string {
	var sb strings.Builder
	now := time.Now().Format("2006-01-02 15:04:05")
	if b.Meta.Date == "" {
		b.Meta.Date = now
	}

	sb.WriteString(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">`)
	sb.WriteString(`<title>WinDiag Pro 检测报告</title><style>`)
	sb.WriteString(`body{font-family:"Segoe UI","Microsoft YaHei",sans-serif;margin:0;background:#f5f7fa;color:#1f2937}`)
	sb.WriteString(`.wrap{max-width:960px;margin:0 auto;padding:32px}`)
	sb.WriteString(`h1{color:#2563eb}h2{border-left:4px solid #2563eb;padding-left:10px;margin-top:32px}`)
	sb.WriteString(`table{width:100%;border-collapse:collapse;margin:12px 0;background:#fff}`)
	sb.WriteString(`th,td{border:1px solid #e5e7eb;padding:8px 10px;text-align:left;font-size:14px}`)
	sb.WriteString(`th{background:#f1f5f9}`)
	sb.WriteString(`.meta td{background:#fff}.score{font-size:48px;font-weight:700;color:#2563eb}`)
	sb.WriteString(`.critical{color:#dc2626;font-weight:600}.high{color:#ea580c;font-weight:600}`)
	sb.WriteString(`.medium{color:#ca8a04}.low{color:#2563eb}.ok{color:#16a34a}`)
	sb.WriteString(`.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px}`)
	sb.WriteString(`</style></head><body><div class="wrap">`)

	sb.WriteString(`<h1>🛡️ WinDiag Pro v5.0 检测报告</h1>`)
	sb.WriteString(`<table class="meta">`)
	row := func(k, v string) { sb.WriteString("<tr><th style='width:160px'>" + k + "</th><td>" + html.EscapeString(v) + "</td></tr>") }
	row("计算机名", b.Meta.Computer)
	row("操作系统", b.Meta.OS)
	row("检测人", b.Meta.Auditor)
	row("日期", b.Meta.Date)
	if b.Meta.Summary != "" {
		row("摘要", b.Meta.Summary)
	}
	sb.WriteString(`</table>`)

	if b.Security != nil {
		s := b.Security
		sb.WriteString(`<h2>🔒 安全检测</h2>`)
		sb.WriteString(fmt.Sprintf(`<p><span class="score">%d</span> / 100 — %s</p>`, s.Score, html.EscapeString(s.Risk)))
		sb.WriteString(`<table><tr><th>时间</th><th>级别</th><th>模块</th><th>描述</th><th>详情</th><th>修复建议</th></tr>`)
		if len(s.Findings) == 0 {
			sb.WriteString(`<tr><td colspan="6" class="ok">未发现安全问题</td></tr>`)
		}
		for _, f := range s.Findings {
			sb.WriteString("<tr><td>" + html.EscapeString(f.Time) + "</td>")
			sb.WriteString(`<td class="` + f.Sev + `">` + sevName(f.Sev) + "</td>")
			sb.WriteString("<td>" + html.EscapeString(f.Cat) + "</td>")
			sb.WriteString("<td>" + html.EscapeString(f.Desc) + "</td>")
			sb.WriteString("<td>" + html.EscapeString(f.Detail) + "</td>")
			sb.WriteString("<td>" + html.EscapeString(f.Fix) + "</td></tr>")
		}
		sb.WriteString(`</table>`)
	}

	if b.Diag != nil {
		d := b.Diag
		sb.WriteString(`<h2>🔬 系统诊断</h2>`)
		sb.WriteString(`<table>`)
		sb.WriteString(fmt.Sprintf("<tr><th>CPU 使用率</th><td>%.1f%%</td></tr>", d.Data.CPU))
		if d.Data.Counters {
			sb.WriteString(fmt.Sprintf("<tr><th>　用户 / 内核 / 中断</th><td>%.1f%% / %.1f%% / %.1f%%</td></tr>", d.Data.CPUUser, d.Data.CPUKernel, d.Data.CPUInterrupt))
			sb.WriteString(fmt.Sprintf("<tr><th>处理器队列长度</th><td>%.0f</td></tr>", d.Data.CPUQueue))
		}
		sb.WriteString(fmt.Sprintf("<tr><th>内存使用率</th><td>%.1f%% (%.1f/%.1f GB)</td></tr>", d.Data.Mem, d.Data.MemUsed, d.Data.MemTotal))
		if d.Data.Counters {
			sb.WriteString(fmt.Sprintf("<tr><th>已提交内存</th><td>%.1f / %.1f GB</td></tr>", d.Data.MemCommit, d.Data.CommitLimit))
			sb.WriteString(fmt.Sprintf("<tr><th>页面错误/秒</th><td>%d</td></tr>", d.Data.PageFaults))
			sb.WriteString(fmt.Sprintf("<tr><th>上下文切换/秒</th><td>%d</td></tr>", d.Data.CtxSwitch))
		}
		sb.WriteString(fmt.Sprintf("<tr><th>磁盘 C: 使用率</th><td>%.1f%%</td></tr>", d.Data.Disk))
		if d.Data.Counters {
			sb.WriteString(fmt.Sprintf("<tr><th>磁盘队列 / 活动时间</th><td>%.2f / %.1f%%</td></tr>", d.Data.DiskQ, d.Data.DiskBusy))
		}
		sb.WriteString(fmt.Sprintf("<tr><th>网络延迟</th><td>%.1f ms</td></tr>", d.Data.NetLatency))
		sb.WriteString(fmt.Sprintf("<tr><th>磁盘 S.M.A.R.T.</th><td>%s</td></tr>", html.EscapeString(d.Data.DiskSmart)))
		sb.WriteString(`</table>`)

		// Physical disk health.
		if len(d.PhysDisks) > 0 {
			sb.WriteString(`<h3>物理磁盘健康</h3><table><tr><th>磁盘</th><th>类型</th><th>接口</th><th>容量</th><th>健康</th><th>S.M.A.R.T.</th><th>温度</th><th>磨损</th></tr>`)
			for _, pd := range d.PhysDisks {
				temp := "—"
				if pd.Temp > 0 {
					temp = fmt.Sprintf("%d °C", pd.Temp)
				}
				wear := "—"
				if pd.Wear > 0 {
					wear = fmt.Sprintf("%d%%", pd.Wear)
				}
				sb.WriteString("<tr><td>" + html.EscapeString(pd.Name) + "</td>")
				sb.WriteString("<td>" + html.EscapeString(pd.Media) + "</td>")
				sb.WriteString("<td>" + html.EscapeString(pd.Bus) + "</td>")
				sb.WriteString(fmt.Sprintf("<td>%.1f GB</td>", pd.SizeGB))
				sb.WriteString("<td>" + html.EscapeString(pd.Health) + "</td>")
				sb.WriteString("<td>" + html.EscapeString(pd.Smart) + "</td>")
				sb.WriteString("<td>" + temp + "</td><td>" + wear + "</td></tr>")
			}
			sb.WriteString(`</table>`)
		}

		// Problem devices.
		if len(d.ProblemDevs) > 0 {
			sb.WriteString(`<h3>问题设备</h3><table><tr><th>设备</th><th>类别</th><th>错误代码</th><th>问题</th></tr>`)
			for _, dev := range d.ProblemDevs {
				sb.WriteString("<tr><td>" + html.EscapeString(dev.Name) + "</td>")
				sb.WriteString("<td>" + html.EscapeString(dev.Class) + "</td>")
				sb.WriteString(fmt.Sprintf("<td>%d</td>", dev.ErrorCode))
				sb.WriteString("<td>" + html.EscapeString(dev.Problem) + "</td></tr>")
			}
			sb.WriteString(`</table>`)
		}

		// Reliability (stability) summary.
		rel := d.Reliability
		sb.WriteString(`<h3>系统可靠性</h3><table>`)
		sb.WriteString(fmt.Sprintf("<tr><th style='width:160px'>稳定性指数</th><td>%.1f / 10 — %s (近 %d 天)</td></tr>", rel.Index, html.EscapeString(rel.Level), rel.WindowDays))
		sb.WriteString(fmt.Sprintf("<tr><th>统计</th><td>应用崩溃 %d · 应用无响应 %d · 蓝屏 %d · 服务故障 %d · 异常关机 %d</td></tr>",
			rel.AppCrashes, rel.AppHangs, rel.BSODs, rel.SvcFailures, rel.UngracefulShutdowns))
		sb.WriteString(`</table>`)
		if len(rel.Events) > 0 {
			sb.WriteString(`<table><tr><th>时间</th><th>类型</th><th>详情</th><th>解决方法</th></tr>`)
			for _, ev := range rel.Events {
				sb.WriteString("<tr><td>" + html.EscapeString(ev.Time) + "</td>")
				sb.WriteString(`<td class="` + ev.Sev + `">` + html.EscapeString(ev.Type) + "</td>")
				sb.WriteString("<td>" + html.EscapeString(ev.Detail) + "</td>")
				sb.WriteString("<td>" + html.EscapeString(ev.Fix) + "</td></tr>")
			}
			sb.WriteString(`</table>`)
		}

		sb.WriteString(`<h3>诊断警告</h3><table><tr><th>级别</th><th>描述</th><th>结果</th><th>建议</th></tr>`)
		if len(d.Warnings) == 0 {
			sb.WriteString(`<tr><td colspan="4" class="ok">未发现诊断警告</td></tr>`)
		}
		for _, w := range d.Warnings {
			sb.WriteString(`<tr><td class="` + w.Sev + `">` + sevName(w.Sev) + "</td>")
			sb.WriteString("<td>" + html.EscapeString(w.Desc) + "</td>")
			sb.WriteString("<td>" + html.EscapeString(w.Result) + "</td>")
			sb.WriteString("<td>" + html.EscapeString(w.Fix) + "</td></tr>")
		}
		sb.WriteString(`</table>`)
	}

	sb.WriteString(`<p style="margin-top:40px;color:#9ca3af;font-size:12px">WinDiag Pro v5.0 — 仅供参考，生成于 ` + now + `</p>`)
	sb.WriteString(`</div></body></html>`)
	return sb.String()
}

func sevName(sev string) string {
	switch sev {
	case models.SevCritical:
		return "严重"
	case models.SevHigh:
		return "高危"
	case models.SevMedium:
		return "中危"
	case models.SevLow:
		return "低危"
	case models.SevOK:
		return "正常"
	case "error":
		return "错误"
	case "info":
		return "信息"
	}
	return sev
}
