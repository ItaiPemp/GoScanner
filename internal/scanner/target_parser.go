package scan

import (
	"errors"
	"io"
	"net"
)

type Target struct {
	address string
	counter int
	current net.IP
	network *net.IPNet
}

func NewTarget(address string) *Target {
	ip, network, err := net.ParseCIDR(address)

	t := &Target{address: address}

	if err == nil {
		t.current = ip.Mask(network.Mask)
		t.network = network
	} else {
		t.current = net.ParseIP(address)
	}

	return t
}

func (t *Target) Next() (net.IP, error) {
	t.counter++
	ip, err := t.currentIP()
	if err != nil {
		return nil, err
	}
	t.incrementIP()
	return ip, nil
}

func (t *Target) Peek() (net.IP, error) {
	return t.currentIP()
}

func (t *Target) currentIP() (net.IP, error) {
	if t.network == nil {
		if t.counter > 1 {
			return nil, io.EOF
		}

		if t.current != nil {
			return t.current, nil
		}

		ips, err := net.LookupIP(t.address)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("no IP addresses found for the target")
		}
		return ips[0], nil
	}

	if t.network.Contains(t.current) {
		ipCopy := make(net.IP, len(t.current))
		copy(ipCopy, t.current)
		return ipCopy, nil
	}

	return nil, io.EOF
}

func (t *Target) incrementIP() {
	for i := len(t.current) - 1; i >= 0; i-- {
		t.current[i]++
		if t.current[i] > 0 {
			break
		}
	}
}
