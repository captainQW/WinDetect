package collector

import (
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	probing "github.com/prometheus-community/pro-bing"
)

func runtimeNumCPU() int { return runtime.NumCPU() }

// pingMS pings host once and returns the RTT in milliseconds, or 0 on failure.
func pingMS(host string) float64 {
	pinger, err := probing.NewPinger(host)
	if err != nil {
		return 0
	}
	pinger.Count = 1
	pinger.Timeout = 2 * time.Second
	pinger.SetPrivileged(true) // Windows requires privileged (raw ICMP)
	if err := pinger.Run(); err != nil {
		return 0
	}
	st := pinger.Statistics()
	if st.PacketsRecv == 0 {
		return 0
	}
	return round1(float64(st.AvgRtt.Microseconds()) / 1000)
}

// knownProcs maps common Windows process names to a friendly description.
var knownProcs = map[string]string{
	"System":             "Windows 系统进程",
	"svchost.exe":        "服务主机进程",
	"explorer.exe":       "Windows 资源管理器",
	"chrome.exe":         "Google Chrome 浏览器",
	"msedge.exe":         "Microsoft Edge 浏览器",
	"firefox.exe":        "Mozilla Firefox 浏览器",
	"lsass.exe":          "本地安全认证子系统",
	"csrss.exe":          "客户端服务器运行时",
	"winlogon.exe":       "Windows 登录进程",
	"services.exe":       "服务控制管理器",
	"dwm.exe":            "桌面窗口管理器",
	"MsMpEng.exe":        "Windows Defender 反恶意软件引擎",
	"code.exe":           "Visual Studio Code",
	"powershell.exe":     "Windows PowerShell",
	"cmd.exe":            "命令提示符",
	"RuntimeBroker.exe":  "运行时代理",
	"SearchIndexer.exe":  "Windows 搜索索引",
}

func procDesc(name string) string {
	if d, ok := knownProcs[name]; ok {
		return d
	}
	return "应用程序"
}

// isSuspicious applies lightweight heuristics to flag a process for review.
func isSuspicious(name string, p *process.Process) bool {
	lower := strings.ToLower(name)
	// System critical names running from a non-system path are suspicious.
	systemNames := []string{"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe"}
	for _, sn := range systemNames {
		if lower == sn {
			exe, err := p.Exe()
			if err == nil && exe != "" {
				le := strings.ToLower(exe)
				if !strings.Contains(le, "\\windows\\system32") &&
					!strings.Contains(le, "\\windows\\syswow64") {
					return true
				}
			}
		}
	}
	// Executables running directly from temp folders warrant attention.
	if exe, err := p.Exe(); err == nil {
		le := strings.ToLower(exe)
		if strings.Contains(le, "\\temp\\") || strings.Contains(le, "\\appdata\\local\\temp") {
			return true
		}
	}
	return false
}
