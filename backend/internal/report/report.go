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
	_ = w.Write([]string{"类别", "时间", "级别", "模块", "描述", "详情", "修复建议"})

	if b.Security != nil {
		for _, f := range b.Security.Findings {
			_ = w.Write([]string{"安全", f.Time, sevName(f.Sev), f.Cat, f.Desc, f.Detail, f.Fix})
		}
	}
	if b.Diag != nil {
		for _, d := range b.Diag.Warnings {
			_ = w.Write([]string{"诊断", b.Diag.ScanTime, sevName(d.Sev), "系统诊断", d.Desc, d.Result, d.Fix})
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
		sb.WriteString(fmt.Sprintf("<tr><th>内存使用率</th><td>%.1f%% (%.1f/%.1f GB)</td></tr>", d.Data.Mem, d.Data.MemUsed, d.Data.MemTotal))
		sb.WriteString(fmt.Sprintf("<tr><th>磁盘 C: 使用率</th><td>%.1f%%</td></tr>", d.Data.Disk))
		sb.WriteString(fmt.Sprintf("<tr><th>网络延迟</th><td>%.1f ms</td></tr>", d.Data.NetLatency))
		sb.WriteString(`</table>`)

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
