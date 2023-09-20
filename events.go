package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"
)

var (
	reSuccessful = `^(\d+) +(\d+\.\d+) +(\w+)+((?:\(\)|\(.+\))) +\= (.+) +<(.+)>`          // pid,ts,syscall,args,returnValue,duration
	reFailed     = `^(\d+) +(\d+\.\d+) +(\w+)+((?:\(\)|\(.+\))) +\= (\-.+) +<(.+)>`        // pid,ts,syscall,args,returnValue,duration
	reUnfinished = `^(\d+) +(\d+\.\d+) +(\w+)+(.+)<unfinished ...>`                        // pid,ts,syscall,args
	reDetached   = `^(\d+) +(\d+\.\d+) <... +(\w+) resumed>+((?:.|.+\))) +\= (.+) +<(.+)>` // pid,ts,syscall,args,returnValue,duration
	reExited     = `^(\d+) +(\d+\.\d+) +(\+\+\+\s+(.*)\s+\+\+\+)`                          // pid,ts,exit status
	reExecve     = `^\(\"([^"]+)\", \[\"([^"]+)\"(\.\.\.)?.*`                              // executable name
	rePrctl      = `^\(PR_SET_NAME, \"([^"]+)\"`                                           // thread name

	regexpSuccessful = regexp.MustCompile(reSuccessful)
	regexpFailed     = regexp.MustCompile(reFailed)
	regexpUnfinished = regexp.MustCompile(reUnfinished)
	regexpDetached   = regexp.MustCompile(reDetached)
	regexpExited     = regexp.MustCompile(reExited)
	regexpExecve     = regexp.MustCompile(reExecve)
	regexpPrctl      = regexp.MustCompile(rePrctl)
)

type Event struct {
	fullTrace string
	Name      string `json:"name"`
	Cat       string `json:"cat"`
	Ph        string `json:"ph"`
	Pid       int    `json:"pid"`
	Tid       int    `json:"tid"`
	Ts        int    `json:"ts"`
	Dur       int    `json:"dur,omitempty"`
	Id        uint64 `json:"id,omitempty"`
	Args      Args   `json:"args"`
}

type Args struct {
	Data        map[string]any `json:"data,omitempty"`
	Name        string         `json:"name,omitempty"`
	CPU         float64        `json:"cpu,omitempty"`
	Memory      uint64         `json:"memory,omitempty"`
	First       string         `json:"first,omitempty"`
	Second      string         `json:"second,omitempty"`
	ReturnValue string         `json:"returnValue,omitempty"`
	DetachedDur int            `json:"detachedDur,omitempty"`
}

func NewEvent(content string) *Event {
	event := Event{fullTrace: content}
	event.getType()
	event.addFields()
	return &event
}

func (e *Event) getType() {
	if regexpFailed.MatchString(e.fullTrace) {
		e.Cat = "failed"
	} else if regexpSuccessful.MatchString(e.fullTrace) {
		e.Cat = "successful"
	} else if regexpUnfinished.MatchString(e.fullTrace) {
		e.Cat = "unfinished"
	} else if regexpDetached.MatchString(e.fullTrace) {
		e.Cat = "detached"
	} else if regexpExited.MatchString(e.fullTrace) {
		e.Cat = "lifetime"
	} else {
		e.Cat = "other"
	}
}

func (e *Event) addFields() {
	groups := e.getReGroups()
	if len(groups) != 0 {
		e.Name = groups[3]
		e.Ts = convertTS(groups[2])
		e.Pid = convertID(groups[1])
		e.Tid = convertID(groups[1])
		e.Args.First = groups[4]
		switch e.Cat {
		case "successful", "failed":
			e.Ph = "X"
			e.Dur = convertTS(groups[6])
			e.Args.First = groups[4]
			e.Args.ReturnValue = groups[5]
		case "detached":
			e.Ph = "X"
			e.Dur = convertTS(groups[6])
			e.Args.Second = groups[4]
			e.Args.ReturnValue = groups[5]
		case "unfinished":
			e.Args.First = groups[4]
			e.Ph = "B"
		case "lifetime":
			e.Name = "lifetime"
			e.Ph = "E"
		}
	}
}

func (e Event) getReGroups() []string {
	switch e.Cat {
	case "successful":
		return regexpSuccessful.FindAllStringSubmatch(e.fullTrace, -1)[0]
	case "failed":
		return regexpFailed.FindAllStringSubmatch(e.fullTrace, -1)[0]
	case "unfinished":
		return regexpUnfinished.FindAllStringSubmatch(e.fullTrace, -1)[0]
	case "detached":
		return regexpDetached.FindAllStringSubmatch(e.fullTrace, -1)[0]
	case "lifetime":
		return regexpExited.FindAllStringSubmatch(e.fullTrace, -1)[0]
	}
	return []string{}
}

type TraceEvents struct {
	Event []*Event `json:"traceEvents"`
}

func (te TraceEvents) Save(output string) {
	b, err := json.MarshalIndent(te.Event, "", " ")
	if err != nil {
		log.Fatalf("[!] Error encoding events to JSON: %s\n", err)
	}
	if err = ioutil.WriteFile(output, b, 0644); err != nil {
		log.Fatalf("[!] Error creating JSON file: %s\n", err)
	}
}

func convertID(id string) int {
	i, err := strconv.Atoi(id)
	if err != nil {
		log.Fatal(err)
	}
	return i
}

func convertTS(ts string) int {
	s := strings.Split(ts, ".")
	if len(s) == 1 {
		return 0
	}
	c := s[0] + s[1]
	i, err := strconv.Atoi(c)
	if err != nil {
		log.Fatal(err)
	}
	return i
}

func merge(events ...[]*Event) []*Event {
	if len(events) == 0 {
		return nil
	}
	l := 0
	{
		i := 0
		for i < len(events) {
			if len(events[i]) == 0 {
				// If this event list is empty, skip it.
				events = append(events[:i], events[i+1:]...)
				continue
			}
			l += len(events[i])
			i++
		}
	}
	merged := make([]*Event, 0, l)
	for len(events) > 0 {
		eventIndex := 0
		firstEvent := events[eventIndex][0]
		for i, e := range events[1:] {
			if firstEvent.Ts <= e[0].Ts {
				continue
			}
			eventIndex = i + 1
			firstEvent = e[0]
		}
		merged = append(merged, events[eventIndex][0])
		if len(events[eventIndex]) == 1 {
			events = append(events[:eventIndex], events[eventIndex+1:]...)
		} else {
			events[eventIndex] = events[eventIndex][1:]
		}
	}
	return merged
}
