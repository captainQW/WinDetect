package collector

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"windetect/internal/models"
	"windetect/internal/winutil"
)

const autorunsTimeout = 120 * time.Second

// autorunsScript enumerates auto-start entries across the persistence
// locations Sysinternals Autoruns inspects — registry Run/RunOnce keys,
// Winlogon Shell/Userinit, AppInit_DLLs, Image File Execution Options
// (debugger hijacks), startup folders, and auto-start services with a
// binary outside the system directory. Each entry's launch target is then
// signature-verified in a single batched call.
const autorunsScript = `$ErrorActionPreference='SilentlyContinue'
$items = New-Object System.Collections.ArrayList

function Add-Item($cat, $loc, $name, $cmd) {
  if ($cmd) { [void]$items.Add([pscustomobject]@{ Category=$cat; Location=$loc; Name=$name; Command=[string]$cmd }) }
}

# Registry Run / RunOnce (HKLM + HKCU)
$runKeys = @(
  @{P='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; C='注册表 Run (HKLM)'},
  @{P='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; C='注册表 RunOnce (HKLM)'},
  @{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; C='注册表 Run (HKCU)'},
  @{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; C='注册表 RunOnce (HKCU)'},
  @{P='HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'; C='注册表 Run (WOW64)'}
)
foreach ($rk in $runKeys) {
  $k = Get-Item $rk.P -ErrorAction SilentlyContinue
  if ($k) { foreach ($n in $k.GetValueNames()) { Add-Item $rk.C $rk.P $n $k.GetValue($n) } }
}

# Winlogon Shell / Userinit
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($wl) {
  Add-Item 'Winlogon' 'Winlogon\Shell' 'Shell' $wl.Shell
  Add-Item 'Winlogon' 'Winlogon\Userinit' 'Userinit' $wl.Userinit
}

# AppInit_DLLs (loaded into every GUI process — classic injection vector)
$ai = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue).AppInit_DLLs
if ($ai) { Add-Item 'AppInit_DLLs' 'Windows\AppInit_DLLs' 'AppInit_DLLs' $ai }

# Image File Execution Options debuggers (image hijacks)
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
  $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
  if ($dbg) { Add-Item '映像劫持 (IFEO)' $_.PSChildName 'Debugger' $dbg }
}

# Startup folders (current user + all users)
$startupDirs = @(
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($d in $startupDirs) {
  Get-ChildItem $d -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
    Add-Item '启动文件夹' $d $_.Name $_.FullName
  }
}

# Auto-start services whose binary is not under the system directory
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
  Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -and $_.PathName -notmatch 'system32|syswow64' } |
  ForEach-Object { Add-Item '自启动服务' 'Win32_Service' $_.Name $_.PathName }

# Resolve the launch executable for each item and batch-verify signatures.
function Resolve-Exe($cmd) {
  if (-not $cmd) { return $null }
  $c = $cmd.Trim()
  if ($c.StartsWith('"')) { $c = ($c -split '"')[1] }
  else { $c = ($c -split ' ')[0] }
  $c = [Environment]::ExpandEnvironmentVariables($c)
  if ($c -and -not [System.IO.Path]::IsPathRooted($c)) {
    $cand = Join-Path $env:WINDIR ('System32\' + $c)
    if (Test-Path $cand) { $c = $cand }
  }
  return $c
}

$paths = @()
foreach ($it in $items) { $it | Add-Member -NotePropertyName Exe -NotePropertyValue (Resolve-Exe $it.Command); if ($it.Exe) { $paths += $it.Exe } }
$uniq = $paths | Where-Object { $_ -and (Test-Path $_ -ErrorAction SilentlyContinue) } | Sort-Object -Unique
$sig = @{}
if ($uniq) {
  Get-AuthenticodeSignature -FilePath $uniq -ErrorAction SilentlyContinue | ForEach-Object {
    $cn = ''
    if ($_.SignerCertificate -and $_.SignerCertificate.Subject -match 'CN=([^,]+)') { $cn = $Matches[1] }
    $sig[$_.Path] = [pscustomobject]@{ Status=[string]$_.Status; Publisher=$cn }
  }
}
foreach ($it in $items) {
  $st = ''
  $pub = ''
  if ($it.Exe -and $sig.ContainsKey($it.Exe)) { $st = $sig[$it.Exe].Status; $pub = $sig[$it.Exe].Publisher }
  $it | Add-Member -NotePropertyName SigStatus -NotePropertyValue $st
  $it | Add-Member -NotePropertyName Publisher -NotePropertyValue $pub
}
$items | Select-Object Category,Location,Name,Command,SigStatus,Publisher | ConvertTo-Json -Depth 3 -Compress`

// collectAutoruns gathers and risk-rates auto-start entries, inspired by
// Sysinternals Autoruns. Entries launching unsigned binaries or living in
// suspicious locations are rated higher.
func collectAutoruns() []models.AutorunEntry {
	var raw []struct {
		Category  string `json:"Category"`
		Location  string `json:"Location"`
		Name      string `json:"Name"`
		Command   string `json:"Command"`
		SigStatus string `json:"SigStatus"`
		Publisher string `json:"Publisher"`
	}
	if err := winutil.RunPSJSONTimeout(autorunsScript, autorunsTimeout, &raw); err != nil || len(raw) == 0 {
		var one struct {
			Category  string `json:"Category"`
			Location  string `json:"Location"`
			Name      string `json:"Name"`
			Command   string `json:"Command"`
			SigStatus string `json:"SigStatus"`
			Publisher string `json:"Publisher"`
		}
		if winutil.RunPSJSONTimeout(autorunsScript, autorunsTimeout, &one) == nil && one.Name != "" {
			raw = append(raw, one)
		} else {
			return nil
		}
	}

	out := make([]models.AutorunEntry, 0, len(raw))
	for _, r := range raw {
		e := models.AutorunEntry{
			Category:  r.Category,
			Location:  r.Location,
			Name:      r.Name,
			Command:   truncate(r.Command, 120),
			Publisher: r.Publisher,
			Signature: sigStatusZh(r.SigStatus),
			Signed:    isSignedValid(r.SigStatus),
		}
		e.Risk = rateAutorun(e, r.Command)
		out = append(out, e)
	}

	// Riskiest first.
	order := map[string]int{"high": 0, "medium": 1, "low": 2, "safe": 3}
	sort.SliceStable(out, func(i, j int) bool {
		return order[out[i].Risk] < order[out[j].Risk]
	})
	return out
}

var tempPathRe = regexp.MustCompile(`(?i)\\temp\\|\\appdata\\local\\temp|\\downloads\\|\\users\\public`)

// rateAutorun assigns a risk band to an autostart entry using signature and
// location signals, mirroring how Autoruns highlights unsigned/odd entries.
func rateAutorun(e models.AutorunEntry, fullCmd string) string {
	lc := strings.ToLower(strings.TrimSpace(fullCmd))
	trusted := isTrustedPublisher(e.Publisher)

	// Recognise the stock Winlogon defaults so they don't false-positive.
	// Default Shell is "explorer.exe"; default Userinit is the system path
	// to userinit.exe (often with a trailing comma).
	if strings.Contains(e.Category, "Winlogon") {
		if e.Name == "Shell" && lc == "explorer.exe" {
			return "safe"
		}
		if e.Name == "Userinit" {
			u := strings.TrimRight(lc, ",")
			if strings.HasSuffix(u, "\\system32\\userinit.exe") || u == "userinit.exe" ||
				strings.HasSuffix(u, "\\windows\\system32\\userinit.exe") {
				return "safe"
			}
		}
	}

	// Highest risk: temp/download locations or invalid signatures.
	if tempPathRe.MatchString(lc) || e.Signature == "签名无效" {
		return "high"
	}
	// Image hijacks and AppInit_DLLs are inherently sensitive vectors.
	if strings.Contains(e.Category, "映像劫持") || strings.Contains(e.Category, "AppInit") {
		if !trusted {
			return "high"
		}
		return "medium"
	}
	if !e.Signed {
		if strings.Contains(lc, "\\appdata\\") || strings.Contains(lc, "\\programdata\\") {
			return "high"
		}
		return "medium"
	}
	if e.Signed && !trusted {
		return "low"
	}
	return "safe"
}
