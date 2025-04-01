package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Color codes
const (
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorReset  = "\033[0m"
)

func checkErr(err error, message string) {
	if err != nil {
		fmt.Printf("%sERROR%s: %s - %v\n", ColorRed, ColorReset, message, err)
		return
	}
}

func main() {
	url := flag.String("url", "https://example.com", "target url")
	flag.Parse()

	// Normalize URL - remove trailing slash if exists
	normalizedUrl := strings.TrimRight(*url, "/")

	robots := fmt.Sprintf("%s/robots.txt", normalizedUrl)
	fmt.Printf("%s[+]%s Fetching robots.txt from: %s%s%s\n",
		ColorGreen, ColorReset, ColorCyan, robots, ColorReset)

	res, err := http.Get(robots)
	checkErr(err, "error get url")
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	checkErr(err, "error membaca body")
	parseRobot(normalizedUrl, string(body))
}

func parseRobot(baseUrl string, data string) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Allow:") || strings.HasPrefix(line, "Disallow:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				path := strings.TrimSpace(parts[1])
				fullUrl := baseUrl + path

				// Skip URLs with wildcards or regex patterns
				if strings.ContainsAny(path, "*?$") {
					fmt.Printf("%s%s%s [%sSKIPPED%s - contains pattern]\n",
						ColorBlue, fullUrl, ColorReset, ColorYellow, ColorReset)
					continue
				}

				// Print the URL being checked
				fmt.Printf("%s[+]%s Checking: %s%s%s\n",
					ColorGreen, ColorReset, ColorCyan, fullUrl, ColorReset)

				resp, err := client.Head(fullUrl)
				if err != nil {
					fmt.Printf("%s%s%s [%sERROR%s: %v]\n",
						ColorBlue, fullUrl, ColorReset, ColorRed, ColorReset, err)
					continue
				}
				resp.Body.Close()

				// Colorize based on status code
				var statusColor string
				switch {
				case resp.StatusCode >= 200 && resp.StatusCode < 300:
					statusColor = ColorGreen
				case resp.StatusCode >= 300 && resp.StatusCode < 400:
					statusColor = ColorYellow
				case resp.StatusCode >= 400 && resp.StatusCode < 500:
					statusColor = ColorRed
				case resp.StatusCode >= 500:
					statusColor = ColorPurple
				default:
					statusColor = ColorReset
				}

				fmt.Printf("%s%s%s [%s%d %s%s]\n",
					ColorBlue, fullUrl, ColorReset,
					statusColor, resp.StatusCode, http.StatusText(resp.StatusCode), ColorReset)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		checkErr(err, "Gagal membaca robots.txt")
	}
}
