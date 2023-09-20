package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type sample struct {
	ts     time.Time
	cpu    float64
	memory uint64
}

// ResourceMonitor polls the state of system resources (RAM, CPU) and can save that
// to a timeseries list that can be visualized in Perfetto.
type ResourceMonitor struct {
	cgroupPath       string
	vCPUs            float64
	timestamp        time.Time
	lastTimestamp    time.Time
	lastCPUUsageUsec uint64
	samples          []sample
}

// NewResourceMonitor returns a new resource monitor.
func NewResourceMonitor() (*ResourceMonitor, error) {
	cgroupBytes, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil, fmt.Errorf("error reading /proc/self/cgroup: %w", err)
	}
	var cgroupPath string
	for _, line := range strings.Split(strings.TrimSpace(string(cgroupBytes)), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 3 {
			continue
		}
		if fields[0] != "0" || fields[1] != "" {
			// We don't support cgroupv1.
			continue
		}
		cgroupPath = "/sys/fs/cgroup" + fields[2]
		break
	}
	if cgroupPath == "" {
		return nil, errors.New("could not find cgroup path")
	}
	cpuMaxBytes, err := os.ReadFile(path.Join(cgroupPath, "cpu.max"))
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %w", path.Join(cgroupPath, "cpu.max"), err)
	}
	quotaMsBytes, timesliceMsBytes, ok := strings.Cut(strings.TrimSpace(string(cpuMaxBytes)), " ")
	if !ok {
		return nil, fmt.Errorf("invalid format for %s: %q", path.Join(cgroupPath, "cpu.max"), string(cpuMaxBytes))
	}
	quotaMs, err := parseUint64(string(quotaMsBytes))
	if err != nil {
		return nil, fmt.Errorf("error parsing %s: %w", path.Join(cgroupPath, "cpu.max"), err)
	}
	timesliceMs, err := parseUint64(string(timesliceMsBytes))
	if err != nil {
		return nil, fmt.Errorf("error parsing %s: %w", path.Join(cgroupPath, "cpu.max"), err)
	}
	vCPUs := float64(quotaMs) / float64(timesliceMs)

	var cpuUsageUsec uint64
	err = readFlatKeyed(path.Join(cgroupPath, "cpu.stat"), map[string]*uint64{
		"usage_usec": &cpuUsageUsec,
	})
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %w", path.Join(cgroupPath, "cpu.stat"), err)
	}

	return &ResourceMonitor{
		cgroupPath:       cgroupPath,
		timestamp:        time.Now(),
		lastTimestamp:    time.Now(),
		lastCPUUsageUsec: cpuUsageUsec,
		vCPUs:            vCPUs,
	}, nil
}

func (r *ResourceMonitor) Run(ctx context.Context) {
	timer := time.NewTicker(1 * time.Millisecond)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		timestamp := time.Now()
		var cpuUsageUsec uint64
		err := readFlatKeyed(path.Join(r.cgroupPath, "cpu.stat"), map[string]*uint64{
			"usage_usec": &cpuUsageUsec,
		})
		if err != nil {
			log.Printf("error reading %s: %v", path.Join(r.cgroupPath, "cpu.stat"), err)
			return
		}
		var memoryAnon uint64
		err = readFlatKeyed(path.Join(r.cgroupPath, "memory.stat"), map[string]*uint64{
			"anon": &memoryAnon,
		})
		if err != nil {
			log.Printf("error reading %s: %v", path.Join(r.cgroupPath, "memory.stat"), err)
			return
		}

		timeDelta := timestamp.Sub(r.lastTimestamp).Microseconds()
		cpuUsage := 100 * float64(cpuUsageUsec-r.lastCPUUsageUsec) /
			r.vCPUs /
			float64(timeDelta)

		r.samples = append(r.samples, sample{
			ts:     timestamp,
			cpu:    cpuUsage,
			memory: uint64(memoryAnon),
		})
		r.lastCPUUsageUsec = cpuUsageUsec
		r.lastTimestamp = timestamp
	}
}

func (r *ResourceMonitor) Events() []*Event {
	events := make([]*Event, 0, len(r.samples)+1)
	events = append(
		events,
		&Event{
			Name: "process_name",
			Ph:   "M",
			Cat:  "__metadata",
			Args: Args{
				Name: "System resources",
			},
		},
		&Event{
			Name: "thread_name",
			Ph:   "M",
			Cat:  "__metadata",
			Args: Args{
				Name: "System resources",
			},
		},
	)
	for _, sample := range r.samples {
		events = append(
			events,
			&Event{
				Ph: "C",
				Ts: int(sample.ts.UnixNano() / 1000),
				Args: Args{
					CPU:    sample.cpu,
					Memory: sample.memory,
				},
			},
		)
	}
	return events
}

func readUint64(p string) (uint64, error) {
	contents, err := os.ReadFile(p)
	if err != nil {
		return 0, err
	}
	v, err := parseUint64(strings.TrimSpace(string(contents)))
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", p, err)
	}
	return v, nil
}

func parseUint64(s string) (uint64, error) {
	if s == "max" {
		return math.MaxUint64, nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return v, nil
}

func readFlatKeyed(p string, kv map[string]*uint64) error {
	contents, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		name, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}

		v, ok := kv[name]
		if !ok {
			continue
		}
		*v, err = parseUint64(value)
		if err != nil {
			return fmt.Errorf("parse %s: %q: %w", p, name, err)
		}
	}

	return nil
}
