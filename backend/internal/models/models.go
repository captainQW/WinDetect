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
	Time   string `json:"time"`
	Sev    string `json:"sev"`
	Cat    string `json:"cat"`    // module/category id label
	CatID  string `json:"catId"`  // module id, used for per-module filtering
	Desc   string `json:"desc"`
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
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
	ScanTime string           `json:"scanTime"`
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
	Time string `json:"time"`
	Src  string `json:"src"`
	Msg  string `json:"msg"`
	Lv   string `json:"lv"` // critical | error | warning | info | security
}

// HWSection is a labelled group of hardware key/values.
type HWSection struct {
	Icon  string `json:"icon"`
	Title string `json:"title"`
	KV    []KV   `json:"kv"`
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

	DiskRd   float64 `json:"diskRd"`
	DiskWr   float64 `json:"diskWr"`
	DiskQ    float64 `json:"diskQ"`
	DiskRdMs float64 `json:"diskRdMs"`
	DiskWrMs float64 `json:"diskWrMs"`

	DNSMs      float64 `json:"dnsMs"`
	GwPing     float64 `json:"gwPing"`
	TCPConn    int     `json:"tcpConn"`
	TCPRetrans float64 `json:"tcpRetrans"`

	DPCLat    float64 `json:"dpcLat"`
	DiskSmart string  `json:"diskSmart"`

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
	Runtimes    []KV           `json:"runtimes"`
	SecUpdates  []KV           `json:"secUpdates"`
	Patches     []Patch        `json:"patches"`
	ScanTime    string         `json:"scanTime"`
}
