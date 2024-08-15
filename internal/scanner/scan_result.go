package scan

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type Result struct {
	Host     net.IP
	Open     []int
	Closed   []int
	Filtered []int
	Latency  time.Duration
	Name     string
}

func NewResult(host net.IP) Result {
	return Result{
		Host:     host,
		Open:     []int{},
		Closed:   []int{},
		Filtered: []int{},
		Latency:  -1,
	}

}

func (r *Result) IsAlive() bool {
	return r.Latency.Seconds() > 0
}

// Report produces a comprehensive summary of the scan results for the host.
func (r *Result) Report() string {
	var builder strings.Builder

	builder.WriteString(fmt.Sprintf("Scan Summary for Host: %s\n", r.Host))

	if r.IsAlive() {
		builder.WriteString(fmt.Sprintf("Host is reachable with a latency of %s\n", r.Latency))
	} else {
		builder.WriteString("Host is not responding\n")
		return builder.String()
	}

	if len(r.Open) > 0 {
		builder.WriteString(fmt.Sprintf("\nOpen Ports:\n%-15s %-8s %s\n", "Port", "Status", "Service"))
		for _, port := range r.Open {
			service := DescribePort(port)
			if knownPort, ok := knownPorts[port]; ok {
				service = knownPort
			}
			builder.WriteString(fmt.Sprintf("%-15s %-8s %s\n", fmt.Sprintf("%d/tcp", port), "Open", service))
		}
	}

	if len(r.Closed) > 0 {
		builder.WriteString(fmt.Sprintf("\nClosed Ports:\n%-15s %-8s %s\n", "Port", "Status", "Service"))
		for _, port := range r.Closed {
			service := DescribePort(port)
			if knownPort, ok := knownPorts[port]; ok {
				service = knownPort
			}
			builder.WriteString(fmt.Sprintf("%-15s %-8s %s\n", fmt.Sprintf("%d/tcp", port), "Closed", service))
		}
	}

	if len(r.Filtered) > 0 {
		builder.WriteString(fmt.Sprintf("\nFiltered Ports: %d ports filtered\n", len(r.Filtered)))
	}

	return builder.String()
}

func ResultOutput(results []Result) {
	for _, result := range results {
		fmt.Println(result.Report())
	}
}
