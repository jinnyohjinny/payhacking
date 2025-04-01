package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ANSI color codes
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ColorBold    = "\033[1m"
)

func main() {
	url := flag.String("url", "https://example.com", "url target")
	flag.Parse()

	// Print banner
	fmt.Printf("%s%sHTTP Header Tester%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%sTesting URL:%s %s%s%s\n\n", ColorYellow, ColorReset, ColorBlue, *url, ColorReset)

	customTransport := &http.Transport{
		ForceAttemptHTTP2: false,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		DisableKeepAlives:     true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
	}

	client := &http.Client{
		Transport: customTransport,
		Timeout:   30 * time.Second,
	}

	// Initial request
	fmt.Printf("%s[+]%s Making initial request...\n", ColorGreen, ColorReset)
	req, err := http.NewRequest("GET", *url, nil)
	if err != nil {
		fmt.Printf("%s[!]%s Error making request: %s%v%s\n", ColorRed, ColorReset, ColorYellow, err, ColorReset)
		return
	}

	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s[!]%s Error performing request: %s%v%s\n", ColorRed, ColorReset, ColorYellow, err, ColorReset)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("%s[!]%s Error reading body: %s%v%s\n", ColorRed, ColorReset, ColorYellow, err, ColorReset)
		return
	}

	originalBody := string(bodyBytes)
	originalStatus := resp.Status
	originalHeaders := resp.Header
	protocol := resp.Proto

	fmt.Printf("\n%s%sBaseline Information:%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%sProtocol:%s %s%s%s\n", ColorYellow, ColorReset, ColorGreen, protocol, ColorReset)
	fmt.Printf("%sStatus Code:%s %s%s%s\n", ColorYellow, ColorReset, statusColor(resp.StatusCode), resp.Status, ColorReset)
	fmt.Printf("%sHeaders Count:%s %s%d%s\n", ColorYellow, ColorReset, ColorGreen, len(resp.Header), ColorReset)

	// Test each header
	fmt.Printf("\n%s%sStarting Header Tests:%s\n", ColorBold, ColorCyan, ColorReset)
	for header := range resp.Header {
		fmt.Printf("\n%s[→]%s Testing Header: %s%s%s\n", ColorMagenta, ColorReset, ColorCyan, header, ColorReset)

		if protocol == "HTTP/2.0" && !isValidHopByHopHeader(header) {
			fmt.Printf("%s[⚠]%s Skipping invalid Connection header for HTTP/2: %s%s%s\n",
				ColorYellow, ColorReset, ColorCyan, header, ColorReset)
			continue
		}

		req, err := http.NewRequest("GET", *url, nil)
		if err != nil {
			fmt.Printf("%s[!]%s Error creating request: %s%v%s\n", ColorRed, ColorReset, ColorYellow, err, ColorReset)
			continue
		}

		req.Header.Set("Connection", header)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		hopResp, err := client.Do(req)
		if err != nil {
			fmt.Printf("%s[!]%s Error: %s%v%s\n", ColorRed, ColorReset, ColorYellow, err, ColorReset)
			continue
		}
		defer hopResp.Body.Close()

		hopBodyBytes, err := io.ReadAll(hopResp.Body)
		if err != nil {
			fmt.Printf("%s[!]%s Error reading response body: %s%v%s\n", ColorRed, ColorReset, ColorYellow, err, ColorReset)
			continue
		}
		hopBody := string(hopBodyBytes)

		// Compare Status Code
		if originalStatus != hopResp.Status {
			fmt.Printf("%s[✗]%s Status Code Changed! %sOriginal=%s %sNew=%s%s\n",
				ColorRed, ColorReset,
				ColorYellow, originalStatus,
				ColorRed, hopResp.Status, ColorReset)
		} else {
			fmt.Printf("%s[✓]%s Status Code Unchanged: %s%s%s\n",
				ColorGreen, ColorReset,
				statusColor(hopResp.StatusCode), hopResp.Status, ColorReset)
		}

		// Compare Body
		if originalBody != hopBody {
			fmt.Printf("%s[✗]%s Body Changed! %sOriginal=%d bytes %sNew=%d bytes%s\n",
				ColorRed, ColorReset,
				ColorYellow, len(originalBody),
				ColorRed, len(hopBody), ColorReset)
		} else {
			fmt.Printf("%s[✓]%s Body Unchanged: %s%d bytes%s\n",
				ColorGreen, ColorReset,
				ColorGreen, len(hopBody), ColorReset)
		}

		// Compare Headers
		headersEqual, diff := compareHeaders(originalHeaders, hopResp.Header)
		if !headersEqual {
			fmt.Printf("%s[✗]%s Header Differences Found:%s\n", ColorRed, ColorReset, ColorReset)
			for _, d := range diff {
				fmt.Printf("  %s- %s%s\n", ColorRed, d, ColorReset)
			}
		} else {
			fmt.Printf("%s[✓]%s Headers Unchanged%s\n", ColorGreen, ColorReset, ColorReset)
		}

		// Final verdict
		if originalStatus == hopResp.Status && originalBody == hopBody && headersEqual {
			fmt.Printf("%s[✔]%s No changes detected (secure)%s\n", ColorGreen, ColorReset, ColorReset)
		} else {
			fmt.Printf("%s[⚠]%s Changes detected (potential vulnerability)%s\n", ColorYellow, ColorReset, ColorReset)
		}
	}
}

func statusColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return ColorGreen
	case code >= 300 && code < 400:
		return ColorYellow
	case code >= 400 && code < 500:
		return ColorRed
	case code >= 500:
		return ColorMagenta
	default:
		return ColorReset
	}
}

func isValidHopByHopHeader(header string) bool {
	hopByHopHeaders := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"TE", "Trailer", "Transfer-Encoding", "Upgrade",
	}

	for _, h := range hopByHopHeaders {
		if strings.EqualFold(header, h) {
			return true
		}
	}
	return false
}

func compareHeaders(original, new http.Header) (bool, []string) {
	ignoreHeaders := map[string]bool{
		"Date":          true,
		"Expires":       true,
		"Last-Modified": true,
		"X-Request-Id":  true,
		"Set-Cookie":    true,
		"Cache-Control": true,
		"Connection":    true,
		"Cf-Ray":        true,
		"Age":           true,
	}

	var differences []string

	for key, values := range original {
		if ignoreHeaders[key] {
			continue
		}

		newValues, exists := new[key]
		if !exists {
			differences = append(differences, fmt.Sprintf("Header '%s' missing in new response", key))
			continue
		}

		if len(values) != len(newValues) {
			differences = append(differences,
				fmt.Sprintf("Header '%s' value count changed (%d → %d)", key, len(values), len(newValues)))
			continue
		}

		for i := range values {
			if strings.TrimSpace(values[i]) != strings.TrimSpace(newValues[i]) {
				differences = append(differences,
					fmt.Sprintf("Header '%s' value changed: '%s' → '%s'", key, values[i], newValues[i]))
			}
		}
	}

	for key := range new {
		if ignoreHeaders[key] {
			continue
		}

		if _, exists := original[key]; !exists {
			differences = append(differences, fmt.Sprintf("New header '%s' appeared", key))
		}
	}

	return len(differences) == 0, differences
}
