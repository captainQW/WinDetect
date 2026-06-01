package collector

import (
	"sort"
	"strings"
	"time"

	"windetect/internal/models"
	"windetect/internal/winutil"
)

// riskScanTimeout bounds the snapshot scan. Signatures are verified in one
// batched call over de-duplicated paths, which keeps this well under the
// limit even on systems with hundreds of drivers and scheduled tasks.
const riskScanTimeout = 150 * time.Second

// riskScanScript gathers processes, kernel drivers and scheduled tasks, then
// resolves every unique executable's Authenticode signature in a single
// batched Get-AuthenticodeSignature call (far faster than per-file checks).
// The result is one JSON object with three arrays plus a path→signature map.
const riskScanScript = `$ErrorActionPreference='SilentlyContinue'

$procs = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } |
  ForEach-Object { [pscustomobject]@{ Name=$_.Name; Path=$_.ExecutablePath; PID=[int]$_.ProcessId } }

$drivers = Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' -and $_.PathName } |
  ForEach-Object {
    $p = $_.PathName -replace '^\\\?\?\\',''
    [pscustomobject]@{ Name=$_.Name; Path=$p }
  }

$tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
  ForEach-Object {
    $exe = ($_.Actions | Select-Object -First 1).Execute
    if ($exe) {
      $exe = [Environment]::ExpandEnvironmentVariables($exe).Trim('"')
      if ($exe -and -not [System.IO.Path]::IsPathRooted($exe)) {
        $cand = Join-Path $env:WINDIR ('System32\' + $exe)
        if (Test-Path $cand) { $exe = $cand }
      }
      [pscustomobject]@{ Name=$_.TaskName; Path=$exe; TaskPath=$_.TaskPath }
    }
  }

# De-duplicate all executable paths, then verify signatures in one batch.
$allPaths = @()
$allPaths += $procs.Path
$allPaths += $drivers.Path
$allPaths += $tasks.Path
$uniq = $allPaths | Where-Object { $_ -and (Test-Path $_ -ErrorAction SilentlyContinue) } | Sort-Object -Unique

$sig = @{}
if ($uniq) {
  Get-AuthenticodeSignature -FilePath $uniq -ErrorAction SilentlyContinue | ForEach-Object {
    $cn = ''
    if ($_.SignerCertificate -and $_.SignerCertificate.Subject -match 'CN=([^,]+)') { $cn = $Matches[1] }
    $sig[$_.Path] = [pscustomobject]@{ Status=[string]$_.Status; Publisher=$cn }
  }
}

[pscustomobject]@{ Procs=$procs; Drivers=$drivers; Tasks=$tasks; Sig=$sig } | ConvertTo-Json -Depth 4 -Compress`

type riskRawProc struct {
	Name string `json:"Name"`
	Path string `json:"Path"`
	PID  int32  `json:"PID"`
}
type riskRawItem struct {
	Name     string `json:"Name"`
	Path     string `json:"Path"`
	TaskPath string `json:"TaskPath"`
}
type riskSig struct {
	Status    string `json:"Status"`
	Publisher string `json:"Publisher"`
}

// collectRiskSnapshot builds an ESET SysInspector-style risk snapshot: it
// enumerates processes, kernel drivers and scheduled tasks, verifies each
// object's Authenticode signature and publisher, then assigns a graded 1-9
// heuristic risk score (color-coded by level). This replaces the previous
// binary "suspicious" flag with weighted, signature-aware scoring.
func collectRiskSnapshot() models.RiskSnapshot {
	snap := models.RiskSnapshot{ScanTime: time.Now().Format("2006-01-02 15:04:05")}

	var raw struct {
		Procs   []riskRawProc      `json:"Procs"`
		Drivers []riskRawItem      `json:"Drivers"`
		Tasks   []riskRawItem      `json:"Tasks"`
		Sig     map[string]riskSig `json:"Sig"`
	}
	if err := winutil.RunPSJSONTimeout(riskScanScript, riskScanTimeout, &raw); err != nil {
		return snap
	}

	// Signature map keys are file paths; normalise to lower-case for lookup.
	sigOf := func(path string) (string, string, bool) {
		for k, v := range raw.Sig {
			if strings.EqualFold(k, path) {
				return sigStatusZh(v.Status), v.Publisher, isSignedValid(v.Status)
			}
		}
		return "未知", "", false
	}

	objs := []models.RiskObject{}
	seen := map[string]bool{}

	for _, p := range raw.Procs {
		key := "p:" + strings.ToLower(p.Path)
		if seen[key] {
			continue
		}
		seen[key] = true
		st, pub, ok := sigOf(p.Path)
		objs = append(objs, models.RiskObject{
			Kind: "process", KindLabel: "进程",
			Name: p.Name, Path: p.Path, PID: p.PID,
			Publisher: pub, Signature: st, Signed: ok,
		})
	}
	for _, d := range raw.Drivers {
		st, pub, ok := sigOf(d.Path)
		objs = append(objs, models.RiskObject{
			Kind: "driver", KindLabel: "内核驱动",
			Name: d.Name, Path: d.Path,
			Publisher: pub, Signature: st, Signed: ok,
		})
	}
	for _, t := range raw.Tasks {
		name := t.Name
		if t.TaskPath != "" {
			name = strings.TrimRight(t.TaskPath, "\\") + "\\" + t.Name
		}
		st, pub, ok := sigOf(t.Path)
		objs = append(objs, models.RiskObject{
			Kind: "task", KindLabel: "计划任务",
			Name: name, Path: t.Path,
			Publisher: pub, Signature: st, Signed: ok,
		})
	}

	for i := range objs {
		scoreRiskObject(&objs[i])
	}

	// Highest risk first, then by kind for stable grouping.
	sort.SliceStable(objs, func(i, j int) bool {
		if objs[i].Score != objs[j].Score {
			return objs[i].Score > objs[j].Score
		}
		return objs[i].Kind < objs[j].Kind
	})

	snap.Objects = objs
	snap.Total = len(objs)
	for _, o := range objs {
		switch o.Level {
		case "safe":
			snap.Safe++
		case "low":
			snap.Low++
		case "medium":
			snap.Medium++
		case "high":
			snap.High++
		}
		if !o.Signed {
			snap.Unsigned++
		}
		if o.Score > snap.TopScore {
			snap.TopScore = o.Score
		}
	}
	return snap
}

// --- scoring -----------------------------------------------------------------

// scoreRiskObject assigns an ESET-style 1-9 risk score using weighted
// heuristics: digital signature status, publisher trust, file location and
// known-sensitive names. Higher score = more suspicious.
func scoreRiskObject(o *models.RiskObject) {
	score := 1 // baseline: signed, trusted location
	reasons := []string{}

	lpath := strings.ToLower(o.Path)
	lname := strings.ToLower(o.Name)
	inSystem := strings.Contains(lpath, "\\windows\\system32") ||
		strings.Contains(lpath, "\\windows\\syswow64") ||
		strings.Contains(lpath, "\\windows\\winsxs")
	// explorer.exe and a few shell binaries legitimately live in the Windows
	// root rather than system32, so treat that as a trusted location too.
	inWindowsRoot := strings.Contains(lpath, "\\windows\\") && !strings.Contains(lpath[strings.Index(lpath, "\\windows\\")+9:], "\\")
	inProgramFiles := strings.Contains(lpath, "\\program files")
	trustedPublisher := isTrustedPublisher(o.Publisher)
	trustedLoc := inSystem || inWindowsRoot || inProgramFiles

	// 1) Signature is the primary trust signal (ESET LiveGrid-style).
	switch {
	case o.Signature == "签名无效":
		score += 5
		reasons = append(reasons, "数字签名无效或已被篡改")
	case !o.Signed && o.Path == "":
		score += 2
		reasons = append(reasons, "无法定位可执行文件路径")
	case !o.Signed:
		score += 4
		reasons = append(reasons, "文件未经数字签名")
	case o.Signed && trustedPublisher:
		reasons = append(reasons, "由可信发行商签名: "+o.Publisher)
	case o.Signed:
		score++
		reasons = append(reasons, "已签名 (发行商: "+pubOrUnknown(o.Publisher)+")")
	}

	// 2) Location heuristics.
	switch {
	case strings.Contains(lpath, "\\temp\\") || strings.Contains(lpath, "\\appdata\\local\\temp"):
		score += 3
		reasons = append(reasons, "运行于临时目录 (恶意软件常见位置)")
	case strings.Contains(lpath, "\\appdata\\") || strings.Contains(lpath, "\\programdata\\"):
		score += 2
		reasons = append(reasons, "运行于用户数据目录")
	case strings.Contains(lpath, "\\downloads\\") || strings.Contains(lpath, "\\users\\public"):
		score += 2
		reasons = append(reasons, "运行于下载/公共目录")
	case !trustedLoc && o.Path != "":
		score++
		reasons = append(reasons, "不在标准系统/程序目录")
	}

	// 3) System-critical names outside their legitimate directory => likely
	// masquerade. A valid signature from a trusted vendor mitigates this.
	critical := map[string]bool{
		"svchost.exe": true, "lsass.exe": true, "csrss.exe": true,
		"services.exe": true, "winlogon.exe": true, "smss.exe": true,
		"wininit.exe": true, "explorer.exe": true,
	}
	if critical[lname] && o.Path != "" && !inSystem && !inWindowsRoot {
		if o.Signed && trustedPublisher {
			score += 2
			reasons = append(reasons, "系统进程名出现在非标准目录 (已签名，建议核实)")
		} else {
			score += 4
			reasons = append(reasons, "系统进程名出现在非系统目录 (疑似伪装)")
		}
	}

	// 4) Kernel drivers carry extra weight when unsigned (rootkit vector).
	if o.Kind == "driver" && !o.Signed {
		score += 2
		reasons = append(reasons, "未签名的内核驱动风险较高 (可能为 Rootkit)")
	}

	// 5) Double extension / suspicious naming.
	if strings.Count(lname, ".") >= 2 &&
		(strings.HasSuffix(lname, ".exe") || strings.HasSuffix(lname, ".scr")) {
		score += 2
		reasons = append(reasons, "可疑的双扩展名")
	}

	if score > 9 {
		score = 9
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "未发现异常特征")
	}

	o.Score = score
	o.Level = riskLevel(score)
	o.Reasons = reasons
	o.Fix = riskFix(o)
}

func riskLevel(score int) string {
	switch {
	case score >= 7:
		return "high"
	case score >= 5:
		return "medium"
	case score >= 3:
		return "low"
	default:
		return "safe"
	}
}

func riskFix(o *models.RiskObject) string {
	switch o.Level {
	case "high":
		if o.Kind == "driver" {
			return "立即将文件上传 VirusTotal 核实；确认为恶意则用专杀工具清除并重启进入安全模式排查"
		}
		return "立即将文件上传 VirusTotal 核实；确认为恶意则结束进程、删除文件并全盘查杀"
	case "medium":
		return "核实该对象来源与发行商是否可信，必要时上传 VirusTotal 检测"
	case "low":
		return "留意该对象，确认是你已知并信任的软件"
	default:
		return "无需处理"
	}
}

// --- helpers -----------------------------------------------------------------

func isSignedValid(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), "Valid")
}

func sigStatusZh(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "valid":
		return "已签名"
	case "notsigned":
		return "未签名"
	case "hashmismatch", "nottrusted":
		return "签名无效"
	default:
		return "未知"
	}
}

func pubOrUnknown(pub string) string {
	if strings.TrimSpace(pub) == "" {
		return "未知"
	}
	return pub
}

// isTrustedPublisher recognises major OS/software vendors so their signed
// binaries stay at the lowest risk, mirroring SysInspector's vendor trust.
func isTrustedPublisher(pub string) bool {
	if pub == "" {
		return false
	}
	p := strings.ToLower(pub)
	trusted := []string{
		"microsoft", "google", "mozilla", "intel", "nvidia", "amd",
		"realtek", "adobe", "apple", "oracle", "vmware", "citrix",
		"lenovo", "dell", "hewlett", "hp inc", "asus", "logitech",
		"tencent", "alibaba", "kingsoft", "valve", "dropbox",
		"red hat", "canonical", "python software",
	}
	for _, t := range trusted {
		if strings.Contains(p, t) {
			return true
		}
	}
	return false
}
