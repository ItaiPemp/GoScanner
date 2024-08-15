package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"github.com/phayes/freeport"
)

var max_size int32 = 65535

type scanJob struct {
	ports   []int // slice of ports to scan
	ip      net.IP
	results chan *Result
	done    chan struct{}
}
type ARPResult struct {
	hwd net.HardwareAddr
	err error
}
type StealthSynScanner struct {
	timeout    time.Duration // timeout for the scan
	target     *Target       // target to scan
	maxWorkers int
	options    gopacket.SerializeOptions
	scanJobs   chan scanJob // channel to send host jobs to workers
}

func NewStealthSynScanner(target *Target, timeout time.Duration, maxWorkers int) *StealthSynScanner {
	return &StealthSynScanner{
		scanJobs:   make(chan scanJob, maxWorkers),
		timeout:    timeout,
		target:     target,
		maxWorkers: maxWorkers,
		options: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
	}
}

func (s *StealthSynScanner) sendARPRequest(handle *pcap.Handle, eth *layers.Ethernet, arp *layers.ARP) error {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.options, eth, arp); err != nil {
		fmt.Printf("Error serializing ARP request: %s\n", err)
		return err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		fmt.Printf("Error sending ARP request: %s\n", err)
		return err
	}
	return nil
}

func receiveARPReply(ctx context.Context, handle *pcap.Handle, arpDst net.IP, resChan chan<- ARPResult) {
	for {
		select {
		case <-ctx.Done(): // if the context is done, return
			resChan <- ARPResult{nil, errors.New("ARP request timed out")}
			return
		default:
			data, _, err := handle.ReadPacketData()
			if err == pcap.NextErrorTimeoutExpired { // if the timeout expired, return
				continue
			} else if err != nil {
				resChan <- ARPResult{nil, err}
				return
			}
			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp := arpLayer.(*layers.ARP)                    // get the ARP layer
				if net.IP(arp.SourceProtAddress).Equal(arpDst) { // if the source IP address is the same as the destination IP address
					resChan <- ARPResult{hwd: net.HardwareAddr(arp.SourceHwAddress), err: nil}
					return
				}

			}
		}
	}
}

func (s *StealthSynScanner) getMACAddr(ctx context.Context, ip net.IP, gateway net.IP, srcIP net.IP, networkInterface *net.Interface) (net.HardwareAddr, error) {
	// get the MAC address of the given IP address
	arpDst := ip
	if gateway != nil {
		arpDst = gateway
	}
	// send an ARP request to the target IP address
	handle, err := pcap.OpenLive(networkInterface.Name, max_size, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("Error opening handle: %s\n", err)
		return nil, err
	}
	defer handle.Close() // close the handle when the function returns

	eth := layers.Ethernet{
		SrcMAC:       networkInterface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(networkInterface.HardwareAddr),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst), // either the target IP or the gateway IP
	}
	s.sendARPRequest(handle, &eth, &arp)
	resChan := make(chan ARPResult)
	ctx, cancel := context.WithTimeout(ctx, time.Second*3) // set a timeout of 3 seconds
	defer cancel()

	go receiveARPReply(ctx, handle, arpDst, resChan)
	select {
	case res := <-resChan:
		return res.hwd, res.err
	case <-ctx.Done():
		return nil, errors.New("ARP request timed out")

	}

}

// populate worker goroutines, which read from the scanJobs channel
func (s *StealthSynScanner) InitWorkers(ctx context.Context) {
	for i := 0; i < s.maxWorkers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-s.scanJobs:
					if len(job.ports) == 0 {
						return
					}
					result, err := s.performScan(ctx, job)
					if err != nil {
						fmt.Printf("Error scanning host: %s", job.ip)
					}
					job.results <- &result
					close(job.done)
				}
			}
		}()
	}
}

func (scanner *StealthSynScanner) performScan(ctx context.Context, task scanJob) (Result, error) {

	scanResult := NewResult(task.ip)
	select {
	case <-ctx.Done():
		return scanResult, nil
	default:
		// continue
	}

	routingHandler, err := routing.New()
	if err != nil {
		return scanResult, err
	}
	interfaceInfo, gateway, localIP, err := routingHandler.Route(task.ip)
	if err != nil {
		return scanResult, err
	}

	packetHandler, err := pcap.OpenLive(interfaceInfo.Name, 65535, true, scanner.timeout) //pcap.BlockForever)
	if err != nil {
		return scanResult, err
	}
	defer packetHandler.Close()

	openPorts := make(chan int)
	closedPorts := make(chan int)
	scanComplete := make(chan struct{})

	startTime := time.Now()

	go func() {
		for {
			select {
			case openPort := <-openPorts:
				if openPort == 0 {
					close(scanComplete)
					return
				}
				if scanResult.Latency < 0 {
					scanResult.Latency = time.Since(startTime)
				}
				for _, port := range scanResult.Open {
					if port == openPort {
						continue
					}
				}
				scanResult.Open = append(scanResult.Open, openPort)
			case closedPort := <-closedPorts:
				if scanResult.Latency < 0 {
					scanResult.Latency = time.Since(startTime)
				}
				for _, port := range scanResult.Closed {
					if port == closedPort {
						continue
					}
				}
				scanResult.Closed = append(scanResult.Closed, closedPort)
			}
		}
	}()

	temporaryPort, err := freeport.GetFreePort()
	if err != nil {
		return scanResult, err
	}

	macAddress, err := scanner.getMACAddr(ctx, task.ip, gateway, localIP, interfaceInfo)
	if err != nil {
		fmt.Printf("MAC address retrieval failed: %s", err)
		return scanResult, err
	}

	ethernetLayer := layers.Ethernet{
		SrcMAC:       interfaceInfo.HardwareAddr,
		DstMAC:       macAddress,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := layers.IPv4{
		SrcIP:    localIP,
		DstIP:    task.ip,
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(temporaryPort),
		DstPort: 0,
		SYN:     true,
	}
	tcpLayer.SetNetworkLayerForChecksum(&ipLayer)

	flow := gopacket.NewFlow(layers.EndpointIPv4, task.ip, localIP)

	ctx, cancel := context.WithTimeout(ctx, scanner.timeout)
	defer cancel()
	portTracker := make(map[int]struct{})
	go func(ctx context.Context) {
		defer close(openPorts)

		eth := &layers.Ethernet{}
		ip4 := &layers.IPv4{}
		tcp := &layers.TCP{}

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, eth, ip4, tcp)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			packetData, _, err := packetHandler.ReadPacketData()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			} else if err == io.EOF {
				return
			} else if err != nil {
				fmt.Printf("Error reading packet: %s\n", err)
				continue
			}

			decodedLayers := []gopacket.LayerType{}
			if err := parser.DecodeLayers(packetData, &decodedLayers); err != nil {
				continue
			}
			for _, layerType := range decodedLayers {
				switch layerType {
				case layers.LayerTypeIPv4:
					if ip4.NetworkFlow() != flow {
						continue
					}
				case layers.LayerTypeTCP:
					port := int(tcp.SrcPort)
					if tcp.DstPort != layers.TCPPort(temporaryPort) {
						continue
					}
					if tcp.SYN && tcp.ACK {
						if _, tracked := portTracker[port]; !tracked {
							portTracker[port] = struct{}{}
							openPorts <- port
						}
					} else if tcp.RST {
						if _, tracked := portTracker[port]; !tracked {
							portTracker[port] = struct{}{}
							closedPorts <- port
						}
					}
				}
			}
		}
	}(ctx)

	for _, port := range task.ports {
		tcpLayer.DstPort = layers.TCPPort(port)
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, scanner.options, &ethernetLayer, &ipLayer, &tcpLayer); err != nil {
			_ = err
		}

		_ = scanner.send_packet(packetHandler, &ethernetLayer, &ipLayer, &tcpLayer)
	}
	<-ctx.Done()
	<-scanComplete
	for _, port := range task.ports {
		if _, tracked := portTracker[port]; !tracked {
			scanResult.Filtered = append(scanResult.Filtered, port)
		}
	}

	return scanResult, nil
}
func (s *StealthSynScanner) send_packet(handle *pcap.Handle, eth *layers.Ethernet, ip4 *layers.IPv4, tcp *layers.TCP) error {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.options, eth, ip4, tcp); err != nil {
		return err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	return nil
}
func (s *StealthSynScanner) InitScan(ctx context.Context, ports []int) ([]Result, error) {

	wg := &sync.WaitGroup{}
	resultChan := make(chan *Result)
	results := []Result{}
	doneChan := make(chan struct{})
	go func() {
		for result := range resultChan {
			results = append(results, *result)
		}
		close(doneChan)
	}()

GenerateJobs:
	for {
		select {
		case <-ctx.Done():
			break GenerateJobs
		default:
			ip, err := s.target.Next()
			if err != nil {
				if err == io.EOF {
					// done generating jobs
					break GenerateJobs
				}
				return nil, err
			}

			wg.Add(1)
			tIP := make([]byte, len(ip))
			copy(tIP, ip)

			// Generate jobs:
			go func(host net.IP, ports []int, wg *sync.WaitGroup) {
				defer wg.Done()
				done := make(chan struct{})

				s.scanJobs <- scanJob{
					results: resultChan,
					ip:      host,
					ports:   ports,
					done:    done,
				}

				<-done
			}(tIP, ports, wg)
		}
	}

	// wait for all jobs
	wg.Wait()
	close(s.scanJobs)
	close(resultChan)
	<-doneChan
	return results, nil
}
