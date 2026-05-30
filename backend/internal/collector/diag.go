package collector

import (
	"fmt"
	stdnet "net"
	"sort"
	"strings"
	"time"

	"windetect/internal/models"
	"windetect/internal/winutil"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// Diagnostics runs a full system diagnostics pass and returns the result.
func Diagnostics() models.DiagResult {
	res := models.DiagResult{ScanTime: time.Now().Format("2006-01-02 15:04:05")}

	data := collectLiveData()
	res.Data = data

	procs := collectProcesses()
	res.Processes = procs
	res.TopCPU = topBy(procs, func(p models.ProcInfo) float64 { return p.CPU }, 10)
	res.TopMem = topBy(procs, func(p models.ProcInfo) float64 { return p.Mem }, 10)
	res.TopIO = topBy(procs, func(p models.ProcInfo) float64 { return p.Total }, 10)

	res.CPUDetail = cpuDetail()
	res.MemDetail, res.MemCompose = memDetail()
	res.Disks = collectDisks()
	res.Adapters = collectAdapters(data)
	res.PingTests = collectPings()
	res.TCPConns = collectTCP()
	res.Services = collectServices()
	res.Hardware = collectHardware()
	res.PhysDisks = collectPhysicalDisks()
	res.ProblemDevs = collectProblemDevices()
	res.Reliability = collectReliability()
	res.Runtimes = collectRuntimes()
	res.SecUpdates = collectSecUpdates()
	res.Patches = collectPatches()
	res.Data.Events = collectEvents()

	// Summarise overall S.M.A.R.T. health from the physical disks.
	res.Data.DiskSmart = overallSmart(res.PhysDisks)
	res.DiskIO = diskIODetail(res.Data)

	res.Warnings = buildWarnings(res)
	return res
}

// overallSmart reduces per-disk health to a single dashboard status.
func overallSmart(disks []models.PhysDisk) string {
	if len(disks) == 0 {
		return "未知"
	}
	worst := "正常"
	for _, d := range disks {
		switch d.Health {
		case "异常":
			return "异常"
		case "警告":
			worst = "警告"
		}
	}
	return worst
}

// collectLiveData samples CPU, memory, disk and network counters.
func collectLiveData() models.DiagData {
	d := models.DiagData{DiskSmart: "正常"}

	// CPU: a short sample window gives a usable instantaneous figure.
	if pcts, err := cpu.Percent(500*time.Millisecond, false); err == nil && len(pcts) > 0 {
		d.CPU = round1(pcts[0])
	}

	if vm, err := mem.VirtualMemory(); err == nil {
		d.Mem = round1(vm.UsedPercent)
		d.MemTotal = round1(bToGB(vm.Total))
		d.MemUsed = round1(bToGB(vm.Used))
		d.MemCache = round1(bToMB(vm.Cached))
	}
	if sw, err := mem.SwapMemory(); err == nil {
		d.PageFile = round1(sw.UsedPercent)
		d.MemCommit = round1(bToGB(sw.Used))
	}

	// Disk C: usage.
	if u, err := disk.Usage("C:"); err == nil {
		d.Disk = round1(u.UsedPercent)
		d.DiskTotal = round1(bToGB(u.Total))
		d.DiskFree = round1(100 - u.UsedPercent)
	}

	// Network throughput sampled over 1 second.
	d.NetUp, d.NetDn = sampleNetThroughput()

	// Latency to a public DNS server (real ICMP round trip).
	d.GwPing = pingMS("8.8.8.8")
	d.NetLatency = d.GwPing

	// Established TCP connections (real count from the socket table).
	if conns, err := net.Connections("tcp"); err == nil {
		est := 0
		for _, c := range conns {
			if c.Status == "ESTABLISHED" {
				est++
			}
		}
		d.TCPConn = est
	}

	// Overlay the real OS performance counters (CPU user/kernel split,
	// context switches, page faults, disk queue/latency, TCP retransmits…).
	// When the perf provider is unavailable d.Counters stays false and the
	// UI suppresses the affected rows rather than showing fabricated numbers.
	applyPerfCounters(&d)

	// Measure DNS resolution latency directly when counters are present,
	// otherwise leave it at zero (the UI hides it).
	d.DNSMs = measureDNS()

	return d
}

// measureDNS times a single DNS lookup of a well-known host in milliseconds.
func measureDNS() float64 {
	start := time.Now()
	if _, err := stdnet.LookupHost("www.microsoft.com"); err != nil {
		return 0
	}
	return round1(float64(time.Since(start).Microseconds()) / 1000)
}

func sampleNetThroughput() (up, dn float64) {
	c1, err := net.IOCounters(false)
	if err != nil || len(c1) == 0 {
		return 0, 0
	}
	time.Sleep(1 * time.Second)
	c2, err := net.IOCounters(false)
	if err != nil || len(c2) == 0 {
		return 0, 0
	}
	up = round1(float64(c2[0].BytesSent-c1[0].BytesSent) / 1024)
	dn = round1(float64(c2[0].BytesRecv-c1[0].BytesRecv) / 1024)
	return up, dn
}

func collectProcesses() []models.ProcInfo {
	procs, err := process.Processes()
	if err != nil {
		return nil
	}
	numCPU := float64(runtimeNumCPU())
	out := make([]models.ProcInfo, 0, len(procs))
	for _, p := range procs {
		name, _ := p.Name()
		if name == "" {
			continue
		}
		cpuPct, _ := p.CPUPercent()
		// gopsutil returns CPU usage summed across cores; normalise.
		cpuPct = cpuPct / numCPU
		mi, _ := p.MemoryInfo()
		var ws, priv float64
		if mi != nil {
			ws = bToMB(mi.RSS)
			priv = bToMB(mi.VMS)
		}
		thr, _ := p.NumThreads()
		info := models.ProcInfo{
			Name: name,
			PID:  p.Pid,
			CPU:  round1(cpuPct),
			Mem:  round1(ws),
			Priv: round1(priv),
			Thr:  thr,
			Susp: isSuspicious(name, p),
			Desc: procDesc(name),
		}
		if io, err := p.IOCounters(); err == nil && io != nil {
			info.Rd = round1(bToMB(io.ReadBytes) / 60)
			info.Wr = round1(bToMB(io.WriteBytes) / 60)
			info.Total = round1(info.Rd + info.Wr)
		}
		out = append(out, info)
	}
	return out
}

func topBy(procs []models.ProcInfo, key func(models.ProcInfo) float64, n int) []models.ProcInfo {
	cp := make([]models.ProcInfo, len(procs))
	copy(cp, procs)
	sort.Slice(cp, func(i, j int) bool { return key(cp[i]) > key(cp[j]) })
	if len(cp) > n {
		cp = cp[:n]
	}
	return cp
}

func cpuDetail() []models.KV {
	kv := []models.KV{}
	if info, err := cpu.Info(); err == nil && len(info) > 0 {
		kv = append(kv,
			models.KV{K: "处理器型号", V: strings.TrimSpace(info[0].ModelName)},
			models.KV{K: "主频", V: fmt.Sprintf("%.2f GHz", info[0].Mhz/1000)},
			models.KV{K: "厂商", V: info[0].VendorID},
		)
	}
	if logical, err := cpu.Counts(true); err == nil {
		kv = append(kv, models.KV{K: "逻辑处理器", V: fmt.Sprintf("%d", logical)})
	}
	if physical, err := cpu.Counts(false); err == nil {
		kv = append(kv, models.KV{K: "物理核心", V: fmt.Sprintf("%d", physical)})
	}
	return kv
}

func memDetail() (detail, compose []models.KV) {
	vm, err := mem.VirtualMemory()
	if err != nil {
		return nil, nil
	}
	detail = []models.KV{
		{K: "物理内存总量", V: fmt.Sprintf("%.1f GB", bToGB(vm.Total))},
		{K: "已使用", V: fmt.Sprintf("%.1f GB", bToGB(vm.Used))},
		{K: "可用", V: fmt.Sprintf("%.1f GB", bToGB(vm.Available))},
		{K: "使用率", V: fmt.Sprintf("%.1f%%", vm.UsedPercent)},
	}
	compose = []models.KV{
		{K: "已用", V: fmt.Sprintf("%.1f GB", bToGB(vm.Used))},
		{K: "缓存", V: fmt.Sprintf("%.1f GB", bToGB(vm.Cached))},
		{K: "可用", V: fmt.Sprintf("%.1f GB", bToGB(vm.Available))},
	}
	return detail, compose
}

func collectDisks() []models.DiskInfo {
	parts, err := disk.Partitions(false)
	if err != nil {
		return nil
	}
	out := []models.DiskInfo{}
	for _, p := range parts {
		u, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		out = append(out, models.DiskInfo{
			Ltr:    strings.TrimSuffix(p.Mountpoint, "\\"),
			FS:     p.Fstype,
			UsePct: round1(u.UsedPercent),
			Used:   round1(bToGB(u.Used)),
			Free:   round1(bToGB(u.Free)),
			Total:  round1(bToGB(u.Total)),
			Type:   "固定磁盘",
		})
	}
	return out
}

func diskIODetail(d models.DiagData) []models.KV {
	kv := []models.KV{
		{K: "磁盘读取/秒", V: fmt.Sprintf("%.1f MB/s", d.DiskRd)},
		{K: "磁盘写入/秒", V: fmt.Sprintf("%.1f MB/s", d.DiskWr)},
		{K: "磁盘队列长度", V: fmt.Sprintf("%.2f", d.DiskQ)},
		{K: "读取延迟", V: fmt.Sprintf("%.1f ms", d.DiskRdMs)},
		{K: "写入延迟", V: fmt.Sprintf("%.1f ms", d.DiskWrMs)},
	}
	if d.Counters {
		kv = append(kv,
			models.KV{K: "磁盘活动时间", V: fmt.Sprintf("%.1f%%", d.DiskBusy)},
			models.KV{K: "磁盘传输/秒 (IOPS)", V: fmt.Sprintf("%.0f", d.DiskIOPS)},
		)
	}
	return kv
}

func collectPings() []models.PingTest {
	hosts := []string{"8.8.8.8", "114.114.114.114", "www.baidu.com"}
	out := make([]models.PingTest, 0, len(hosts))
	for _, h := range hosts {
		ms := pingMS(h)
		out = append(out, models.PingTest{Host: h, OK: ms > 0, MS: ms})
	}
	return out
}

func collectTCP() []models.TCPConn {
	conns, err := net.Connections("tcp")
	if err != nil {
		return nil
	}
	out := []models.TCPConn{}
	for _, c := range conns {
		if c.Status != "ESTABLISHED" {
			continue
		}
		proc := ""
		if c.Pid > 0 {
			if p, err := process.NewProcess(c.Pid); err == nil {
				proc, _ = p.Name()
			}
		}
		out = append(out, models.TCPConn{
			Local:  fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port),
			Remote: c.Raddr.IP,
			Port:   fmt.Sprintf("%d", c.Raddr.Port),
			State:  c.Status,
			Proc:   proc,
		})
		if len(out) >= 50 {
			break
		}
	}
	return out
}

func collectHardware() []models.HWSection {
	secs := []models.HWSection{}
	if hi, err := host.Info(); err == nil {
		kv := []models.KV{
			{K: "主机名", V: hi.Hostname},
			{K: "操作系统", V: fmt.Sprintf("%s %s", hi.Platform, hi.PlatformVersion)},
			{K: "内核版本", V: hi.KernelVersion},
			{K: "架构", V: hi.KernelArch},
			{K: "运行时间", V: fmt.Sprintf("%.1f 小时", float64(hi.Uptime)/3600)},
		}
		// Augment with perfmon-style system identity from WMI.
		var os struct {
			Caption     string `json:"Caption"`
			Version     string `json:"Version"`
			Build       string `json:"BuildNumber"`
			InstallDate string `json:"InstallDate"`
			LastBoot    string `json:"LastBootUpTime"`
		}
		if err := winutil.RunPSJSON(`Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,@{N='InstallDate';E={$_.InstallDate.ToString('yyyy-MM-dd')}},@{N='LastBootUpTime';E={$_.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')}} | ConvertTo-Json -Compress`, &os); err == nil && os.Caption != "" {
			kv = []models.KV{
				{K: "主机名", V: hi.Hostname},
				{K: "操作系统", V: strings.TrimSpace(os.Caption)},
				{K: "版本号", V: fmt.Sprintf("%s (Build %s)", os.Version, os.Build)},
				{K: "架构", V: hi.KernelArch},
				{K: "安装日期", V: os.InstallDate},
				{K: "上次启动", V: os.LastBoot},
				{K: "运行时间", V: fmt.Sprintf("%.1f 小时", float64(hi.Uptime)/3600)},
			}
		}
		secs = append(secs, models.HWSection{Icon: "🖥️", Title: "系统", KV: kv})
	}
	// Computer manufacturer / model (perfmon system summary).
	var cs struct {
		Manufacturer string `json:"Manufacturer"`
		Model        string `json:"Model"`
		SystemType   string `json:"SystemType"`
	}
	if err := winutil.RunPSJSON(`Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,SystemType | ConvertTo-Json -Compress`, &cs); err == nil && (cs.Manufacturer != "" || cs.Model != "") {
		secs = append(secs, models.HWSection{
			Icon: "🏷️", Title: "计算机",
			KV: []models.KV{
				{K: "厂商", V: cs.Manufacturer},
				{K: "型号", V: cs.Model},
				{K: "系统类型", V: cs.SystemType},
			},
		})
	}
	if info, err := cpu.Info(); err == nil && len(info) > 0 {
		secs = append(secs, models.HWSection{
			Icon: "⚡", Title: "处理器",
			KV: []models.KV{
				{K: "型号", V: strings.TrimSpace(info[0].ModelName)},
				{K: "主频", V: fmt.Sprintf("%.2f GHz", info[0].Mhz/1000)},
				{K: "缓存", V: fmt.Sprintf("%d KB", info[0].CacheSize)},
			},
		})
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		secs = append(secs, models.HWSection{
			Icon: "💾", Title: "内存",
			KV: []models.KV{
				{K: "总容量", V: fmt.Sprintf("%.1f GB", bToGB(vm.Total))},
			},
		})
	}
	// Augment with WMI-sourced BIOS / board / GPU info.
	secs = append(secs, hardwareWMI()...)
	return secs
}

func buildWarnings(res models.DiagResult) []models.DiagWarning {
	w := []models.DiagWarning{}
	d := res.Data
	if d.CPU >= 85 {
		w = append(w, models.DiagWarning{Sev: models.SevHigh, Desc: "CPU 使用率过高",
			Result: fmt.Sprintf("当前 %.0f%%", d.CPU), Fix: "检查高占用进程，结束异常任务"})
	}
	if d.Mem >= 85 {
		w = append(w, models.DiagWarning{Sev: models.SevHigh, Desc: "内存使用率过高",
			Result: fmt.Sprintf("当前 %.0f%%", d.Mem), Fix: "关闭占用内存的程序或增加物理内存"})
	}
	if d.DiskFree <= 10 {
		w = append(w, models.DiagWarning{Sev: models.SevMedium, Desc: "系统盘剩余空间不足",
			Result: fmt.Sprintf("剩余 %.0f%%", d.DiskFree), Fix: "清理临时文件或扩容磁盘"})
	}
	if d.NetLatency > 100 {
		w = append(w, models.DiagWarning{Sev: models.SevMedium, Desc: "网络延迟偏高",
			Result: fmt.Sprintf("%.0f ms", d.NetLatency), Fix: "检查网络连接质量"})
	}

	// Real performance-counter driven warnings (parity with perfmon /report).
	if d.Counters {
		if d.CPUQueue >= 4 {
			w = append(w, models.DiagWarning{Sev: models.SevMedium, Desc: "处理器队列偏长",
				Result: fmt.Sprintf("队列长度 %.0f", d.CPUQueue),
				Fix:    "存在 CPU 资源争用，检查高占用进程或增加核心"})
		}
		if d.DiskQ >= 5 {
			w = append(w, models.DiagWarning{Sev: models.SevMedium, Desc: "磁盘队列长度过高",
				Result: fmt.Sprintf("队列 %.1f", d.DiskQ),
				Fix:    "磁盘 I/O 可能成为瓶颈，检查高 I/O 进程或升级存储"})
		}
		if d.CommitLimit > 0 && d.MemCommit/d.CommitLimit > 0.9 {
			w = append(w, models.DiagWarning{Sev: models.SevHigh, Desc: "已提交内存接近上限",
				Result: fmt.Sprintf("%.1f / %.1f GB", d.MemCommit, d.CommitLimit),
				Fix:    "增加物理内存或扩大页面文件"})
		}
	}

	// Disk S.M.A.R.T. / health warnings.
	for _, pd := range res.PhysDisks {
		switch pd.Health {
		case "异常":
			w = append(w, models.DiagWarning{Sev: models.SevCritical, Desc: "磁盘健康状态异常",
				Result: pd.Name + " — " + pd.Smart, Fix: "立即备份数据并更换磁盘"})
		case "警告":
			w = append(w, models.DiagWarning{Sev: models.SevHigh, Desc: "磁盘健康状态警告",
				Result: pd.Name + " — " + pd.Smart, Fix: "尽快备份数据并计划更换磁盘"})
		}
		if pd.Wear >= 90 {
			w = append(w, models.DiagWarning{Sev: models.SevMedium, Desc: "固态硬盘磨损偏高",
				Result: fmt.Sprintf("%s 磨损 %d%%", pd.Name, pd.Wear),
				Fix:    "SSD 写入寿命接近上限，建议规划更换"})
		}
	}

	// Device Manager problem devices (perfmon flags these prominently).
	if n := len(res.ProblemDevs); n > 0 {
		first := res.ProblemDevs[0]
		w = append(w, models.DiagWarning{Sev: models.SevMedium,
			Desc:   fmt.Sprintf("检测到 %d 个问题设备", n),
			Result: fmt.Sprintf("%s: %s", first.Name, first.Problem),
			Fix:    "在设备管理器中更新或重新安装相关驱动程序"})
	}

	// System stability (Reliability Monitor parity).
	rel := res.Reliability
	if rel.BSODs > 0 {
		w = append(w, models.DiagWarning{Sev: models.SevCritical, Desc: "近期发生系统蓝屏",
			Result: fmt.Sprintf("最近 %d 天内 %d 次", rel.WindowDays, rel.BSODs),
			Fix:    "分析 Minidump 定位故障驱动，运行内存诊断 (mdsched.exe)"})
	}
	if rel.Index > 0 && rel.Index < 7 {
		sev := models.SevMedium
		if rel.Index < 4 {
			sev = models.SevHigh
		}
		w = append(w, models.DiagWarning{Sev: sev, Desc: "系统稳定性偏低",
			Result: fmt.Sprintf("稳定性指数 %.1f/10 (崩溃%d 无响应%d 服务%d 异常关机%d)",
				rel.Index, rel.AppCrashes, rel.AppHangs, rel.SvcFailures, rel.UngracefulShutdowns),
			Fix: "查看\"可靠性\"页定位高频故障来源并按建议修复"})
	}

	return w
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}

func bToGB(b uint64) float64 { return float64(b) / 1024 / 1024 / 1024 }
func bToMB(b uint64) float64 { return float64(b) / 1024 / 1024 }
