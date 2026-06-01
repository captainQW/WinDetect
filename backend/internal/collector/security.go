package collector

import (
	"time"

	"windetect/internal/models"
)

// moduleDef describes a security detection module's static metadata
// and the function that performs its scan.
type moduleDef struct {
	id   string
	icon string
	name string
	desc string
	scan func() ([]models.Finding, []map[string]string)
}

// securityModules is the ordered list of detection modules.
func securityModules() []moduleDef {
	return []moduleDef{
		{"firewall", "🧱", "防火墙", "Windows 防火墙配置检测", scanFirewall},
		{"defender", "🛡️", "Defender 防病毒", "病毒防护与实时保护检测", scanDefender},
		{"update", "🔄", "系统更新", "Windows 更新与补丁检测", scanUpdate},
		{"account", "👤", "账户安全", "用户账户与权限检测", scanAccounts},
		{"network", "🌐", "网络安全", "开放端口与连接检测", scanNetwork},
		{"startup", "🚀", "启动项", "自启动程序检测", scanStartup},
		{"uac", "🔐", "用户账户控制", "UAC 与安全策略检测", scanUAC},
		{"shares", "📁", "共享与远程", "网络共享与远程访问检测", scanShares},
		{"hardening", "🛠️", "安全基线", "CIS 基线与系统加固检测", scanHardening},
	}
}

// Security runs all security modules and aggregates the result.
func Security() models.SecurityResult {
	now := time.Now().Format("2006-01-02 15:04:05")
	res := models.SecurityResult{
		ScanTime: now,
		Summary:  map[string]string{},
	}

	allFindings := []models.Finding{}
	for _, m := range securityModules() {
		findings, data := m.scan()
		for i := range findings {
			findings[i].Cat = m.name
			findings[i].CatID = m.id
			if findings[i].Time == "" {
				findings[i].Time = now
			}
		}
		status := "clean"
		if len(findings) > 0 {
			status = "warn"
		}
		res.Modules = append(res.Modules, models.SecurityModule{
			ID:       m.id,
			Icon:     m.icon,
			Name:     m.name,
			Desc:     m.desc,
			Status:   status,
			Findings: findings,
			Data:     data,
		})
		allFindings = append(allFindings, findings...)
	}

	res.Findings = allFindings
	res.Score = computeScore(allFindings)
	res.RiskIcon, res.Risk, res.RiskDesc = riskBand(res.Score)
	res.Summary = buildSecSummary(allFindings)
	res.Mitre = buildMitreSummary(allFindings)
	return res
}

// buildMitreSummary aggregates findings by MITRE ATT&CK technique so the UI
// can present a coverage view (referenced in the requirements appendix 10.1).
func buildMitreSummary(findings []models.Finding) []models.MitreHit {
	idx := map[string]*models.MitreHit{}
	order := []string{}
	rank := map[string]int{
		models.SevCritical: 4, models.SevHigh: 3, models.SevMedium: 2, models.SevLow: 1,
	}
	for _, f := range findings {
		if f.Mitre == "" {
			continue
		}
		h, ok := idx[f.Mitre]
		if !ok {
			h = &models.MitreHit{ID: f.Mitre, Name: f.MitreNm, Sev: f.Sev}
			idx[f.Mitre] = h
			order = append(order, f.Mitre)
		}
		h.Count++
		if rank[f.Sev] > rank[h.Sev] {
			h.Sev = f.Sev
		}
	}
	out := make([]models.MitreHit, 0, len(order))
	for _, id := range order {
		out = append(out, *idx[id])
	}
	return out
}

// computeScore derives a 0-100 security score from finding severities.
func computeScore(findings []models.Finding) int {
	score := 100
	for _, f := range findings {
		switch f.Sev {
		case models.SevCritical:
			score -= 20
		case models.SevHigh:
			score -= 12
		case models.SevMedium:
			score -= 6
		case models.SevLow:
			score -= 2
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func riskBand(score int) (icon, title, desc string) {
	switch {
	case score >= 90:
		return "✅", "安全状况良好", "系统安全配置符合最佳实践，未发现重大风险"
	case score >= 75:
		return "🟢", "安全状况尚可", "存在少量需要关注的安全项，建议尽快处理"
	case score >= 50:
		return "🟠", "存在安全风险", "检测到多项安全问题，建议及时修复"
	default:
		return "🔴", "安全风险较高", "系统存在严重安全隐患，请立即处理"
	}
}

func buildSecSummary(findings []models.Finding) map[string]string {
	crit, high, med, low := 0, 0, 0, 0
	for _, f := range findings {
		switch f.Sev {
		case models.SevCritical:
			crit++
		case models.SevHigh:
			high++
		case models.SevMedium:
			med++
		case models.SevLow:
			low++
		}
	}
	return map[string]string{
		"严重": itoa(crit),
		"高危": itoa(high),
		"中危": itoa(med),
		"低危": itoa(low),
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
