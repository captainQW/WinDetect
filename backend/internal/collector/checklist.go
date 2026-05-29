package collector

// ChecklistItem is a single verification task.
type ChecklistItem struct {
	ID       string `json:"id"`
	Text     string `json:"text"`
	Important bool  `json:"important"`
	Done     bool   `json:"done"`
}

// ChecklistCategory groups related checklist items with a diagnostic command.
type ChecklistCategory struct {
	ID    string          `json:"id"`
	Icon  string          `json:"icon"`
	Title string          `json:"title"`
	Cmd   string          `json:"cmd"`
	Items []ChecklistItem `json:"items"`
}

// Checklist returns the system inspection checklist definition.
func Checklist() []ChecklistCategory {
	return []ChecklistCategory{
		{
			ID: "perf", Icon: "⚡", Title: "性能检查",
			Cmd: "perfmon /report",
			Items: []ChecklistItem{
				{ID: "perf-cpu", Text: "CPU 使用率正常 (<80%)", Important: true},
				{ID: "perf-mem", Text: "内存使用率正常 (<80%)", Important: true},
				{ID: "perf-disk", Text: "磁盘剩余空间充足 (>15%)", Important: true},
				{ID: "perf-startup", Text: "启动项数量合理", Important: false},
			},
		},
		{
			ID: "security", Icon: "🛡️", Title: "安全检查",
			Cmd: "Get-MpComputerStatus",
			Items: []ChecklistItem{
				{ID: "sec-fw", Text: "防火墙已启用", Important: true},
				{ID: "sec-av", Text: "防病毒软件运行中", Important: true},
				{ID: "sec-update", Text: "系统更新为最新", Important: true},
				{ID: "sec-uac", Text: "UAC 已开启", Important: false},
			},
		},
		{
			ID: "network", Icon: "🌐", Title: "网络检查",
			Cmd: "Test-NetConnection 8.8.8.8",
			Items: []ChecklistItem{
				{ID: "net-conn", Text: "网络连接正常", Important: true},
				{ID: "net-dns", Text: "DNS 解析正常", Important: true},
				{ID: "net-ports", Text: "无异常开放端口", Important: false},
			},
		},
		{
			ID: "storage", Icon: "💿", Title: "存储检查",
			Cmd: "Get-PhysicalDisk | Get-StorageReliabilityCounter",
			Items: []ChecklistItem{
				{ID: "stg-smart", Text: "磁盘 S.M.A.R.T. 状态正常", Important: true},
				{ID: "stg-temp", Text: "已清理临时文件", Important: false},
			},
		},
	}
}
