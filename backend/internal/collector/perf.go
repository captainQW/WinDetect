package collector

import (
	"windetect/internal/models"
	"windetect/internal/winutil"
)

// perfRaw mirrors the JSON emitted by the combined performance-counter script.
// Values come from the Win32_PerfFormattedData_* WMI classes, whose property
// names are language independent (unlike localized Get-Counter paths), so the
// same query works on Chinese and English editions of Windows.
type perfRaw struct {
	CpuUser       float64 `json:"CpuUser"`
	CpuKernel     float64 `json:"CpuKernel"`
	CpuInterrupt  float64 `json:"CpuInterrupt"`
	CpuDPC        float64 `json:"CpuDPC"`
	Interrupts    int64   `json:"Interrupts"`
	CtxSwitch     int64   `json:"CtxSwitch"`
	SysCalls      int64   `json:"SysCalls"`
	CpuQueue      float64 `json:"CpuQueue"`
	PageFaults    int64   `json:"PageFaults"`
	AvailMB       float64 `json:"AvailMB"`
	CommitLimit   float64 `json:"CommitLimit"`
	Committed     float64 `json:"Committed"`
	Cache         float64 `json:"Cache"`
	PoolPaged     float64 `json:"PoolPaged"`
	PoolNonPaged  float64 `json:"PoolNonPaged"`
	CommitPct     float64 `json:"CommitPct"`
	DiskRd        float64 `json:"DiskRd"`
	DiskWr        float64 `json:"DiskWr"`
	DiskQueue     float64 `json:"DiskQueue"`
	DiskRdSec     float64 `json:"DiskRdSec"`
	DiskWrSec     float64 `json:"DiskWrSec"`
	DiskTime      float64 `json:"DiskTime"`
	DiskXfer      float64 `json:"DiskXfer"`
	TcpEst        int64   `json:"TcpEst"`
	TcpRetransSeg float64 `json:"TcpRetransSeg"`
	TcpSeg        float64 `json:"TcpSeg"`
}

// perfCounterScript samples the formatted performance-data classes twice with a
// short gap so rate counters (per-second values) stabilise before reading.
const perfCounterScript = `$ErrorActionPreference='SilentlyContinue'
Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" | Out-Null
Start-Sleep -Milliseconds 700
$cpu  = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'"
$sys  = Get-CimInstance Win32_PerfFormattedData_PerfOS_System
$mem  = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
$disk = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'"
$tcp  = Get-CimInstance Win32_PerfFormattedData_Tcpip_TCPv4
[pscustomobject]@{
  CpuUser       = [double]$cpu.PercentUserTime
  CpuKernel     = [double]$cpu.PercentPrivilegedTime
  CpuInterrupt  = [double]$cpu.PercentInterruptTime
  CpuDPC        = [double]$cpu.PercentDPCTime
  Interrupts    = [int64]$cpu.InterruptsPersec
  CtxSwitch     = [int64]$sys.ContextSwitchesPersec
  SysCalls      = [int64]$sys.SystemCallsPersec
  CpuQueue      = [double]$sys.ProcessorQueueLength
  PageFaults    = [int64]$mem.PageFaultsPersec
  AvailMB       = [double]$mem.AvailableMBytes
  CommitLimit   = [double]$mem.CommitLimit
  Committed     = [double]$mem.CommittedBytes
  Cache         = [double]$mem.CacheBytes
  PoolPaged     = [double]$mem.PoolPagedBytes
  PoolNonPaged  = [double]$mem.PoolNonpagedBytes
  CommitPct     = [double]$mem.PercentCommittedBytesInUse
  DiskRd        = [double]$disk.DiskReadBytesPersec
  DiskWr        = [double]$disk.DiskWriteBytesPersec
  DiskQueue     = [double]$disk.CurrentDiskQueueLength
  DiskRdSec     = [double]$disk.AvgDisksecPerRead
  DiskWrSec     = [double]$disk.AvgDisksecPerWrite
  DiskTime      = [double]$disk.PercentDiskTime
  DiskXfer      = [double]$disk.DiskTransfersPersec
  TcpEst        = [int64]$tcp.ConnectionsEstablished
  TcpRetransSeg = [double]$tcp.SegmentsRetransmittedPersec
  TcpSeg        = [double]$tcp.SegmentsPersec
} | ConvertTo-Json -Compress`

// applyPerfCounters fills d with real OS performance counters. When the query
// fails (e.g. the perf provider is unavailable) d is left untouched and the
// caller keeps the gopsutil-derived snapshot, with d.Counters left false.
func applyPerfCounters(d *models.DiagData) {
	var p perfRaw
	if err := winutil.RunPSJSON(perfCounterScript, &p); err != nil {
		return
	}

	d.Counters = true

	// CPU breakdown.
	d.CPUUser = round1(p.CpuUser)
	d.CPUKernel = round1(p.CpuKernel)
	d.CPUInterrupt = round1(p.CpuInterrupt)
	d.CPUQueue = round1(p.CpuQueue)
	d.Interrupts = p.Interrupts
	d.DPCLat = round1(p.CpuDPC) // now % DPC time (real), no longer a fabricated µs value

	// System.
	if p.CtxSwitch > 0 {
		d.CtxSwitch = p.CtxSwitch
	}
	d.SysCalls = p.SysCalls

	// Memory.
	d.PageFaults = p.PageFaults
	d.MemAvailMB = round1(p.AvailMB)
	d.MemCommit = round1(bToGB(uint64(p.Committed)))
	d.CommitLimit = round1(bToGB(uint64(p.CommitLimit)))
	d.MemCache = round1(bToMB(uint64(p.Cache)))
	d.PoolPaged = round1(bToMB(uint64(p.PoolPaged)))
	d.PoolNonPaged = round1(bToMB(uint64(p.PoolNonPaged)))

	// Disk (_Total across physical disks).
	d.DiskRd = round1(p.DiskRd / 1024 / 1024)
	d.DiskWr = round1(p.DiskWr / 1024 / 1024)
	d.DiskQ = round1(p.DiskQueue)
	d.DiskRdMs = round1(p.DiskRdSec * 1000)
	d.DiskWrMs = round1(p.DiskWrSec * 1000)
	d.DiskBusy = round1(p.DiskTime)
	d.DiskIOPS = round1(p.DiskXfer)

	// TCP.
	if p.TcpEst > 0 {
		d.TCPConn = int(p.TcpEst)
	}
	if p.TcpSeg > 0 {
		d.TCPRetrans = round1(p.TcpRetransSeg / p.TcpSeg * 100)
	} else {
		d.TCPRetrans = 0
	}
}
