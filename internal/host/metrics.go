// Package host collects point-in-time VM resource usage (CPU, memory, disk). The agent runs in a
// container, but CPU/memory in /proc are NOT namespaced (they reflect the host), and a Statfs on a
// host bind-mount reflects the host filesystem — so these read the real VM, no host PID/privileges.
package host

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Metrics is a snapshot of the VM's resource usage.
type Metrics struct {
	CPUPercent     float64
	MemTotalBytes  uint64
	MemUsedBytes   uint64
	DiskTotalBytes uint64
	DiskUsedBytes  uint64
}

// Collect gathers host CPU%, memory, and disk usage. diskPath is any host-backed path (a bind mount)
// whose filesystem is the VM's — its Statfs reflects the VM disk.
func Collect(diskPath string) Metrics {
	m := Metrics{CPUPercent: cpuPercent()}
	m.MemTotalBytes, m.MemUsedBytes = memUsage()
	m.DiskTotalBytes, m.DiskUsedBytes = diskUsage(diskPath)
	return m
}

// DirSize returns the total size (bytes) of all files under path. A missing/unreadable path returns 0, and
// unreadable entries are skipped so a partial dir still reports what it can — used for the disk breakdown.
func DirSize(path string) uint64 {
	var total uint64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // skip unreadable entries rather than abort the walk
		}
		if info, ierr := d.Info(); ierr == nil {
			total += uint64(info.Size())
		}
		return nil
	})
	return total
}

// diskUsage returns total + used bytes of the filesystem backing path.
func diskUsage(path string) (total, used uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	bsize := uint64(st.Bsize)
	total = st.Blocks * bsize
	avail := st.Bavail * bsize // free to non-root
	if total < avail {
		return total, 0
	}
	return total, total - avail
}

// memUsage returns total + used bytes from /proc/meminfo (used = total - available).
func memUsage() (total, used uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	var memTotal, memAvail uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := meminfoKB(line, "MemTotal:"); ok {
			memTotal = v
		} else if v, ok := meminfoKB(line, "MemAvailable:"); ok {
			memAvail = v
		}
	}
	if memTotal == 0 || memAvail > memTotal {
		return memTotal, 0
	}
	return memTotal, memTotal - memAvail
}

// meminfoKB parses a "Key:  <n> kB" line into bytes.
func meminfoKB(line, key string) (uint64, bool) {
	if !strings.HasPrefix(line, key) {
		return 0, false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, false
	}
	kb, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return kb * 1024, true
}

// cpuPercent samples /proc/stat twice ~200ms apart and returns busy% over that interval.
func cpuPercent() float64 {
	total1, idle1, ok := cpuTimes()
	if !ok {
		return 0
	}
	time.Sleep(200 * time.Millisecond)
	total2, idle2, ok := cpuTimes()
	if !ok || total2 <= total1 {
		return 0
	}
	totalDelta := float64(total2 - total1)
	idleDelta := float64(idle2 - idle1)
	pct := (1 - idleDelta/totalDelta) * 100
	if pct < 0 {
		return 0
	}
	return pct
}

// cpuTimes reads the aggregate "cpu" line of /proc/stat, returning total jiffies + idle jiffies.
func cpuTimes() (total, idle uint64, ok bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, 0, false
	}
	fields := strings.Fields(sc.Text()) // cpu user nice system idle iowait irq softirq steal ...
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	for i := 1; i < len(fields); i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			continue
		}
		total += v
		if i == 4 { // idle
			idle = v
		}
	}
	return total, idle, true
}
