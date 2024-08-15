package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	scan "goscanner/internal/scanner"

	"github.com/briandowns/spinner"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

const logo string = `
  ____      ____                                  
 / ___| ___/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
| |  _ / _ \___ \ / __/ _ | '_ \| '_ \ / _ \ '__|
| |_| | (_) |__) | (_| (_| | | | | | | |  __/ |   
 \____|\___/____/ \___\__,_|_| |_|_| |_|\___|_|   

 `

var (
	logoStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#01FAC6")).Bold(true)
	endingMsgStyle = lipgloss.NewStyle().PaddingLeft(1).Foreground(lipgloss.Color("170")).Bold(true)
)

var rootCmd = &cobra.Command{
	Use:   "goscanner",
	Short: "GoScanner is a simple&fast network/port scanner written in Go",
	Run: func(cmd *cobra.Command, args []string) {
		ports, err := parsePorts(ports)
		ctx, cancel := context.WithCancel(context.Background())
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			<-c
			fmt.Println("Scan cancelled. Requesting stop...")
			cancel()
		}()

		fmt.Printf("%s\n", logoStyle.Render(logo))
		startTime := time.Now()
		// loop over the targets
		for _, target := range args {
			spinner := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
			spinner.Suffix = "Scanning Host: " + target + "..."
			spinner.Color("cyan")
			spinner.Start()

			targetParser := scan.NewTarget(target)
			scanner := scan.NewStealthSynScanner(targetParser, time.Millisecond*time.Duration(timeout), maxWrokers)
			// init workers goroutines
			scanner.InitWorkers(ctx)
			// begin scan
			results, err := scanner.InitScan(ctx, ports)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			spinner.Stop()
			fmt.Println()
			scan.ResultOutput(results)
		}
		// fmt.Printf(endingMsgStyle.Render("Scan completed in %s\n", time.Since(startTime)))
		fmt.Printf("%s%s\n", endingMsgStyle.Render("Scan completed in "), time.Since(startTime))

	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var timeout int = 2000
var maxWrokers int = 500
var ports string = ""

func init() {
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout-ms", "t", timeout, "Scan timeout in MS")
	rootCmd.PersistentFlags().IntVarP(&maxWrokers, "workers", "w", maxWrokers, "maximum number of workers")
	rootCmd.PersistentFlags().StringVarP(&ports, "ports", "p", ports, "Commas seperated list of ports to scan. Example: 80,443,8080. A range input is also supported: 1-1000")
}

func parsePorts(ports string) ([]int, error) {
	if ports == "" {
		return scan.DefaultPorts, nil
	}
	var portSlice []int
	portStrings := strings.Split(ports, ",")

	for _, portStr := range portStrings {
		portStr = strings.TrimSpace(portStr)
		if portStr == "" {
			continue
		}

		// Check if the portStr is a range
		if strings.Contains(portStr, "-") {
			rangeParts := strings.Split(portStr, "-")
			if len(rangeParts) != 2 {
				return nil, errors.New("invalid port range format: " + portStr)
			}

			startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, errors.New("invalid start of port range: " + rangeParts[0])
			}

			endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, errors.New("invalid end of port range: " + rangeParts[1])
			}

			if startPort < 1 || endPort > 65535 || startPort > endPort {
				return nil, errors.New("port range out of bounds: " + portStr)
			}

			for port := startPort; port <= endPort; port++ {
				portSlice = append(portSlice, port)
			}
		} else {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, errors.New("invalid port format: " + portStr)
			}

			if port < 1 || port > 65535 {
				return nil, errors.New("port out of range: " + portStr)
			}

			portSlice = append(portSlice, port)
		}
	}

	return portSlice, nil
}
