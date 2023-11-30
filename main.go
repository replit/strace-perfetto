package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

var (
	flagSyscalls = flag.String("e", "", "only trace specified syscalls")
	flagOutput   = flag.String("o", "stracefile.json", "json output file")
	flagTimeout  = flag.Duration("t", time.Duration(0), "strace timeout")
)

var (
	// -f trace child processes
	// -T time spent in each syscall
	// -ttt timestamp of each event (microseconds)
	// -q don't display process attach / personality changes
	defaultStraceArgs = []string{"-f", "-T", "-ttt", "-q"}
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] command\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	flag.Parse()

	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// run strace
	userStraceArgs := []string{}
	if *flagSyscalls != "" {
		userStraceArgs = append(userStraceArgs, "-e", *flagSyscalls)
	}
	userStraceArgs = append(userStraceArgs, flag.Args()...)

	tmp, err := os.CreateTemp("", "stracefile")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	defaultStraceArgs = append(defaultStraceArgs, "-o", tmp.Name())

	resourceMonitor, err := NewResourceMonitor()
	if err != nil {
		log.Printf("cpu / memory will not be available: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	strace := Strace{
		DefaultArgs: defaultStraceArgs,
		UserArgs:    userStraceArgs,
		Timeout:     *flagTimeout,
	}
	if resourceMonitor != nil {
		go resourceMonitor.Run(ctx)
	}
	strace.Run()
	cancel()

	// parse results
	var syscallEvents []*Event
	preserved := make(map[string]*Event) // [pid+syscall]*Event
	scanner := bufio.NewScanner(tmp)

	var resourceMonitorEvents []*Event
	if resourceMonitor != nil {
		resourceMonitorEvents = resourceMonitor.Events()
	}

	liveThreads := make(map[int]bool)
	for scanner.Scan() {
		e := NewEvent(scanner.Text())
		if e.Cat == "other" {
			continue
		}
		alive := liveThreads[e.Tid]
		if !alive {
			syscallEvents = append(syscallEvents, &Event{
				Name: "lifetime",
				Cat:  "lifetime",
				Ph:   "B",
				Ts:   e.Ts,
				Pid:  e.Pid,
				Tid:  e.Tid,
			})
			liveThreads[e.Tid] = true
		}
		switch {
		case e.Cat == "unfinished":
			k := strconv.Itoa(e.Pid) + e.Name
			preserved[k] = e
		case e.Cat == "detached":
			k := strconv.Itoa(e.Pid) + e.Name
			p := preserved[k]
			e.Dur = e.Ts - p.Ts
			e.Ts = p.Ts
			e.Args.First = p.Args.First
			syscallEvents = append(syscallEvents, e)
			delete(preserved, k)
		case e.Cat == "lifetime":
			syscallEvents = append(syscallEvents, e)
		case e.Cat == "other":
			break
		default:
			syscallEvents = append(syscallEvents, e)
		}
	}
	// add any unfinished/preserved traces to events
	for _, p := range preserved {
		p.Ph = "i" // instant event
		syscallEvents = append(syscallEvents, p)
	}

	processNames := make(map[int]string)
	threadNames := make(map[int]string)
	processThreads := make(map[int]int)
	processThreads[syscallEvents[0].Tid] = syscallEvents[0].Pid
	// First construct the process tree. This is needed because sometimes the
	// fork/clone syscall returns after the thread has started executing and
	// some syscalls have been called.
	for _, e := range syscallEvents {
		pid, ok := processThreads[e.Tid]
		if ok {
			e.Pid = pid
		}
		if e.Name == "fork" || strings.HasPrefix(e.Name, "clone") {
			childTid, err := strconv.Atoi(e.Args.ReturnValue)
			if err == nil {
				if strings.Contains(e.Args.First, "CLONE_THREAD") {
					processThreads[childTid] = e.Pid
				} else {
					processThreads[childTid] = childTid
				}
			}
		}
	}
	for _, e := range syscallEvents {
		pid, ok := processThreads[e.Tid]
		if ok {
			e.Pid = pid
		}
		if e.Name == "fork" || strings.HasPrefix(e.Name, "clone") {
			childTid, err := strconv.Atoi(e.Args.ReturnValue)
			if err == nil {
				if strings.Contains(e.Args.First, "CLONE_THREAD") {
					processThreads[childTid] = e.Pid
				} else {
					processThreads[childTid] = childTid
				}
			}
		}
	}
	// Now we can get the process names and flows between parent/children.
	var metadataEvents []*Event
	var nextFlowId uint64
	for _, e := range syscallEvents {
		pid, ok := processThreads[e.Tid]
		if ok {
			e.Pid = pid
		}
		if e.Name == "prctl" && strings.Contains(e.Args.First, "PR_SET_NAME") {
			threadName := e.Args.First
			m := regexpPrctl.FindStringSubmatch(threadName)
			if len(m) == 2 {
				threadName = m[1]
			}
			threadNames[e.Tid] = threadName
		}
		if e.Name == "execve" {
			processName := e.Args.First
			m := regexpExecve.FindStringSubmatch(processName)
			if len(m) == 4 {
				processName = m[2]
				if m[3] == "..." {
					processName = path.Base(m[1])
				}
			}
			processNames[e.Pid] = processName
			threadNames[e.Tid] = processName
		}
		if e.Name == "write" {
			m := regexpGlobalEvent.FindStringSubmatch(e.Args.First)
			if len(m) == 2 {
				metadataEvents = append(
					metadataEvents,
					&Event{
						Name:  strings.TrimSpace(m[1]),
						Cat:   "event",
						Ph:    "i",
						Pid:   e.Pid,
						Tid:   e.Tid,
						Scope: "g",
						Ts:    e.Ts,
					},
				)
			}
		}
		if e.Name == "fork" || strings.HasPrefix(e.Name, "clone") {
			childTid, err := strconv.Atoi(e.Args.ReturnValue)
			if err == nil {
				metadataEvents = append(
					metadataEvents,
					&Event{
						Name: e.Name,
						Cat:  "clone",
						Ph:   "s",
						Pid:  e.Pid,
						Tid:  e.Tid,
						Ts:   e.Ts + 1,
						Id:   nextFlowId,
					},
				)
				threadNames[childTid] = threadNames[e.Tid]
				if strings.Contains(e.Args.First, "CLONE_THREAD") {
					metadataEvents = append(
						metadataEvents,
						&Event{
							Name: e.Name,
							Cat:  "clone",
							Ph:   "f",
							Pid:  e.Pid,
							Tid:  childTid,
							Ts:   e.Ts + 1,
							Id:   nextFlowId,
						},
					)
				} else {
					metadataEvents = append(
						metadataEvents,
						&Event{
							Name: e.Name,
							Cat:  "clone",
							Ph:   "f",
							Pid:  childTid,
							Tid:  childTid,
							Ts:   e.Ts + 1,
							Id:   nextFlowId,
						},
					)
					processNames[childTid] = processNames[e.Pid]
				}
				nextFlowId++
			}
		}
	}
	for pid, name := range processNames {
		metadataEvents = append(
			metadataEvents,
			&Event{
				Name: "process_name",
				Ph:   "M",
				Pid:  pid,
				Tid:  pid,
				Cat:  "__metadata",
				Args: Args{
					Name: name,
				},
			},
		)
	}
	for tid, name := range threadNames {
		metadataEvents = append(
			metadataEvents,
			&Event{
				Name: "thread_name",
				Ph:   "M",
				Tid:  tid,
				Pid:  processThreads[tid],
				Cat:  "__metadata",
				Args: Args{
					Name: name,
				},
			},
		)
	}

	// Finally, merge all the event sources
	events := merge(metadataEvents, syscallEvents, resourceMonitorEvents)

	// save results
	te := TraceEvents{events}
	te.Save(*flagOutput)

	fmt.Printf("[+] Trace file saved to: %s\n", *flagOutput)
	fmt.Printf("[+] Analyze results: %s\n", "https://ui.perfetto.dev/")
}
