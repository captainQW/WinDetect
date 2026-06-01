package models

// Severity levels used across security findings and diagnostic warnings.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevOK       = "ok"
)

// Finding represents a single security issue discovered during a scan.
type Finding struct {
	Time   string   `json:"time"`
	Sev    string   `json:"sev"`
	Cat    string   `json:"cat"`    // module/category id label
	CatID  string   `json:"catId"`  // module id, used for per-module filtering
	Desc   string   `json:"desc"`
	Detail string   `json:"detail"`
	Fix    string   `json:"fix"`    // short summary (kept for reports/CSV)
	Steps  []string `json:"steps"`  // ordered, detailed remediation steps
	Cmd    string   `json:"cmd"`    // ready-to-run command (PowerShell/cmd)
	Ref    string   `json:"ref"`    // optional reference / docs note
	Mitre  string   `json:"mitre"`  // MITRE ATT&CK technique id, e.g. T1021.001
	MitreNm string  `json:"mitreNm"` // MITRE technique name (zh)
	CIS    string   `json:"cis"`    // related CIS Benchmark control reference
}

// SecurityModule describes a detection module and its discovered findings.
type SecurityModule struct {
	ID       string              `json:"id"`
	Icon     string              `json:"icon"`
	Name     string              `json:"name"`
	Desc     string              `json:"desc"`
	Status   string              `json:"status"` // clean | warn | pending
	Findings []Finding           `json:"findings"`
	Data     []map[string]string `json:"data"` // tabular detection data rows
}

// SecurityResult is the full payload of a security scan.
type SecurityResult struct {
	Score    int              `json:"score"`
	RiskIcon string           `json:"riskIcon"`
	Risk     string           `json:"riskTitle"`
	RiskDesc string           `json:"riskDesc"`
	Summary  map[string]string `json:"summary"`
	Modules  []SecurityModule `json:"modules"`
	Findings []Finding        `json:"findings"`
	Mitre    []MitreHit       `json:"mitre"` // ATT&CK techniques matched by findings
	ScanTime string           `json:"scanTime"`
}

// MitreHit summarises a MITRE ATT&CK technique triggered by one or more findings.
type MitreHit struct {
	ID    string `json:"id"`    // e.g. T1021.001
	Name  string `json:"name"`  // technique name (zh)
	Count int    `json:"count"` // how many findings mapped to it
	Sev   string `json:"sev"`   // highest severity among them
}

// KV is a simple ordered key/value pair for display tables.
type KV struct {
	K string `json:"k"`
	V string `json:"v"`
}

// ProcInfo holds per-process metrics.
type ProcInfo struct {
	Name  string  `json:"name"`
	PID   int32   `json:"pid"`
	CPU   float64 `json:"cpu"`
	Mem   float64 `json:"mem"`   // working set MB
	Priv  float64 `json:"priv"`  // private MB
	Rd    float64 `json:"rd"`    // read MB/s
	Wr    float64 `json:"wr"`    // write MB/s
	Total float64 `json:"total"` // total IO MB/s
	Thr   int32   `json:"thr"`
	Susp  bool    `json:"susp"`
	Desc  string  `json:"desc"`
}

// DiskInfo describes a logical disk volume.
type DiskInfo struct {
	Ltr    string  `json:"ltr"`
	FS     string  `json:"fs"`
	UsePct float64 `json:"usePct"`
	Used   float64 `json:"used"`
	Free   float64 `json:"free"`
	Total  float64 `json:"total"`
	Type   string  `json:"type"`
}

// NetAdapter describes a network interface.
type NetAdapter struct {
	Name   string  `json:"name"`
	Type   string  `json:"type"`
	IP     string  `json:"ip"`
	MAC    string  `json:"mac"`
	Speed  string  `json:"speed"`
	UpKbps float64 `json:"up_kbps"`
	DnKbps float64 `json:"dn_kbps"`
}

// PingTest holds a connectivity probe result.
type PingTest struct {
	Host string  `json:"host"`
	OK   bool    `json:"ok"`
	MS   float64 `json:"ms"`
}

// TCPConn describes an established TCP connection.
type TCPConn struct {
	Local  string `json:"local"`
	Remote string `json:"remote"`
	Port   string `json:"port"`
	State  string `json:"state"`
	Proc   string `json:"proc"`
}

// ServiceInfo describes a Windows service.
type ServiceInfo struct {
	Name  string `json:"name"`
	Disp  string `json:"disp"`
	State string `json:"state"`
	Start string `json:"start"`
	Acct  string `json:"acct"`
}

// EventLog is a single Windows event log entry.
type EventLog struct {
	Time   string   `json:"time"`
	Src    string   `json:"src"`
	Msg    string   `json:"msg"`
	Lv     string   `json:"lv"` // critical | error | warning | info | security
	ID     int      `json:"id"` // Windows event id
	Cause  string   `json:"cause"`  // likely cause in plain language
	Fix    string   `json:"fix"`    // short remediation summary
	Steps  []string `json:"steps"`  // detailed remediation steps
	Cmd    string   `json:"cmd"`    // optional command to investigate/fix
}

// ReliabilityEvent is a stability-relevant record (crash, hang, install…)
// used to build a Windows "Reliability Monitor"-style timeline.
type ReliabilityEvent struct {
	Time   string `json:"time"`
	Type   string `json:"type"`   // 应用崩溃 / 应用无响应 / 蓝屏 / 系统错误 / 更新 / 警告
	Sev    string `json:"sev"`    // critical | error | medium | info
	Source string `json:"source"`
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
}

// ReliabilityResult summarises system stability over the recent period,
// mirroring the data behind Windows Reliability Monitor (perfmon /rel).
type ReliabilityResult struct {
	Index       float64            `json:"index"`       // 1-10 stability index estimate
	Level       string             `json:"level"`       // 稳定 / 一般 / 不稳定
	WindowDays  int                `json:"windowDays"`  // analysis window in days
	AppCrashes  int                `json:"appCrashes"`
	AppHangs    int                `json:"appHangs"`
	BSODs       int                `json:"bsods"`
	SvcFailures int                `json:"svcFailures"`
	UngracefulShutdowns int        `json:"ungracefulShutdowns"`
	Events      []ReliabilityEvent `json:"events"`
}

// RiskObject is a single inspected object (process, driver, scheduled task,
// startup item…) with a heuristic risk score, inspired by ESET SysInspector's
// per-object color-coded risk model.
type RiskObject struct {
	Kind      string   `json:"kind"`      // process | driver | task | startup
	KindLabel string   `json:"kindLabel"` // 进程 / 内核驱动 / 计划任务 / 启动项
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	Publisher string   `json:"publisher"`
	Signature string   `json:"signature"` // 已签名(可信) / 已签名 / 未签名 / 签名无效 / 未知
	Signed    bool     `json:"signed"`
	PID       int32    `json:"pid"`
	Score     int      `json:"score"`     // 1-9 (9 = highest risk), ESET-style
	Level     string   `json:"level"`     // safe | low | medium | high
	Reasons   []string `json:"reasons"`   // why this score was assigned
	Fix       string   `json:"fix"`       // recommended action
}

// RiskSnapshot aggregates all inspected objects with risk statistics,
// modelled on ESET SysInspector's filterable system snapshot.
type RiskSnapshot struct {
	ScanTime  string       `json:"scanTime"`
	Total     int          `json:"total"`
	Safe      int          `json:"safe"`
	Low       int          `json:"low"`
	Medium    int          `json:"medium"`
	High      int          `json:"high"`
	Unsigned  int          `json:"unsigned"`
	TopScore  int          `json:"topScore"`
	Objects   []RiskObject `json:"objects"`
}

// AutorunEntry is a single auto-start item discovered across the many Windows
// persistence locations Sysinternals Autoruns inspects (Run keys, Winlogon,
// services, startup folders, image hijacks, etc.), with signature info.
type AutorunEntry struct {
	Category  string `json:"category"`  // 注册表 Run / Winlogon / 服务 / 启动文件夹 / 映像劫持 …
	Location  string `json:"location"`  // the registry path or folder
	Name      string `json:"name"`
	Command   string `json:"command"`
	Publisher string `json:"publisher"`
	Signature string `json:"signature"` // 已签名 / 未签名 / 签名无效 / 未知
	Signed    bool   `json:"signed"`
	Risk      string `json:"risk"` // safe | low | medium | high
}

// HWSection is a labelled group of hardware key/values.
type HWSection struct {
	Icon  string `json:"icon"`
	Title string `json:"title"`
	KV    []KV   `json:"kv"`
}

// PhysDisk describes a physical disk with health / reliability data,
// mirroring the "Disk" section of a perfmon system diagnostics report.
type PhysDisk struct {
	Name        string  `json:"name"`
	Media       string  `json:"media"` // SSD / HDD / Unspecified
	Bus         string  `json:"bus"`   // NVMe / SATA / USB ...
	SizeGB      float64 `json:"sizeGB"`
	Health      string  `json:"health"` // 正常 / 警告 / 异常
	Smart       string  `json:"smart"`  // S.M.A.R.T. summary
	Temp        int     `json:"temp"`   // °C, 0 if unknown
	Wear        int     `json:"wear"`   // % wear (SSD), 0 if unknown
	ReadErrors  int64   `json:"readErrors"`
	WriteErrors int64   `json:"writeErrors"`
	PowerOnHrs  int64   `json:"powerOnHours"`
}

// ProblemDevice is a Device Manager device reporting an error, matching the
// "problem devices" warnings produced by perfmon /report.
type ProblemDevice struct {
	Name      string `json:"name"`
	Class     string `json:"class"`
	Status    string `json:"status"`
	ErrorCode int    `json:"errorCode"`
	Problem   string `json:"problem"`
}

// Patch is a pending Windows update.
type Patch struct {
	KB   string `json:"kb"`
	Desc string `json:"desc"`
	Type string `json:"type"`
	Date string `json:"date"`
	Sev  string `json:"sev"`
}

// DiagData is the live metrics snapshot used by the dashboard and overview.
type DiagData struct {
	CPU        float64 `json:"cpu"`
	Mem        float64 `json:"mem"`
	MemUsed    float64 `json:"memUsed"`
	MemTotal   float64 `json:"memTotal"`
	Disk       float64 `json:"disk"`
	DiskTotal  float64 `json:"diskTotal"`
	DiskFree   float64 `json:"diskFree"`
	NetLatency float64 `json:"netLatency"`
	NetUp      float64 `json:"netUp"`
	NetDn      float64 `json:"netDn"`

	CtxSwitch int64   `json:"ctxSwitch"`
	SysCalls  int64   `json:"sysCalls"`
	MemCommit float64 `json:"memCommit"`
	MemCache  float64 `json:"memCache"`
	PageFaults int64  `json:"pageFaults"`
	PageFile  float64 `json:"pageFile"`

	// CPU breakdown (real, from perf counters when available).
	CPUUser   float64 `json:"cpuUser"`   // % user/processor time
	CPUKernel float64 `json:"cpuKernel"` // % privileged time
	CPUInterrupt float64 `json:"cpuInterrupt"` // % interrupt time
	CPUQueue  float64 `json:"cpuQueue"`  // processor queue length
	Interrupts int64  `json:"interrupts"` // interrupts/sec

	// Memory detail (real, from perf counters when available).
	MemAvailMB   float64 `json:"memAvailMB"`
	CommitLimit  float64 `json:"commitLimit"`  // GB
	PoolPaged    float64 `json:"poolPaged"`    // MB
	PoolNonPaged float64 `json:"poolNonPaged"` // MB

	DiskRd   float64 `json:"diskRd"`
	DiskWr   float64 `json:"diskWr"`
	DiskQ    float64 `json:"diskQ"`
	DiskRdMs float64 `json:"diskRdMs"`
	DiskWrMs float64 `json:"diskWrMs"`
	DiskBusy float64 `json:"diskBusy"` // % disk time
	DiskIOPS float64 `json:"diskIops"` // transfers/sec

	DNSMs      float64 `json:"dnsMs"`
	GwPing     float64 `json:"gwPing"`
	TCPConn    int     `json:"tcpConn"`
	TCPRetrans float64 `json:"tcpRetrans"`

	DPCLat    float64 `json:"dpcLat"`
	DiskSmart string  `json:"diskSmart"`

	// Counters indicates whether the real-counter fields above were
	// populated from the OS. When false the UI hides synthetic estimates.
	Counters bool `json:"counters"`

	Events []EventLog `json:"events"`
}

// DiagWarning is a diagnostic warning surfaced on the overview.
type DiagWarning struct {
	Sev    string `json:"sev"`
	Desc   string `json:"desc"`
	Result string `json:"result"`
	Fix    string `json:"fix"`
}

// DiagResult is the full payload of a system diagnostics scan.
type DiagResult struct {
	Data        DiagData       `json:"data"`
	Warnings    []DiagWarning  `json:"warnings"`
	TopCPU      []ProcInfo     `json:"topCpu"`
	TopMem      []ProcInfo     `json:"topMem"`
	TopIO       []ProcInfo     `json:"topIo"`
	Processes   []ProcInfo     `json:"processes"`
	CPUDetail   []KV           `json:"cpuDetail"`
	MemDetail   []KV           `json:"memDetail"`
	MemCompose  []KV           `json:"memCompose"`
	Disks       []DiskInfo     `json:"disks"`
	DiskIO      []KV           `json:"diskIo"`
	Adapters    []NetAdapter   `json:"adapters"`
	PingTests   []PingTest     `json:"pingTests"`
	TCPConns    []TCPConn      `json:"tcpConns"`
	Services    []ServiceInfo  `json:"services"`
	Hardware    []HWSection    `json:"hardware"`
	PhysDisks   []PhysDisk     `json:"physDisks"`
	ProblemDevs []ProblemDevice `json:"problemDevs"`
	Reliability ReliabilityResult `json:"reliability"`
	Risk        RiskSnapshot   `json:"risk"`
	Autoruns    []AutorunEntry `json:"autoruns"`
	Runtimes    []KV           `json:"runtimes"`
	SecUpdates  []KV           `json:"secUpdates"`
	Patches     []Patch        `json:"patches"`
	ScanTime    string         `json:"scanTime"`
}
