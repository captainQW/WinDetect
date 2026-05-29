package collector

import (
	"time"

	"windetect/internal/models"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
)

// QuickData returns a lightweight live snapshot for header gauges.
// It avoids the heavier PowerShell/WMI calls so it can be polled often.
func QuickData() models.DiagData {
	d := models.DiagData{}
	if pcts, err := cpu.Percent(200*time.Millisecond, false); err == nil && len(pcts) > 0 {
		d.CPU = round1(pcts[0])
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		d.Mem = round1(vm.UsedPercent)
		d.MemTotal = round1(bToGB(vm.Total))
		d.MemUsed = round1(bToGB(vm.Used))
	}
	if u, err := disk.Usage("C:"); err == nil {
		d.Disk = round1(u.UsedPercent)
		d.DiskTotal = round1(bToGB(u.Total))
		d.DiskFree = round1(100 - u.UsedPercent)
	}
	return d
}
