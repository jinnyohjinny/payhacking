package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
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
	ColorDim     = "\033[2m"
)

type Config struct {
	TargetURL string
	UserAgent string
	Threads   int
}

type HeaderCheck struct {
	URL    string
	Header http.Header
	Check  string
}

type Scanner struct {
	config       Config
	httpClient   *http.Client
	reflectCount int
	mu           sync.Mutex
}

func main() {
	// Print banner
	fmt.Printf("%s%sHTTP Header Reflection Scanner%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s%s%s\n", ColorDim, strings.Repeat("─", 60), ColorReset)

	config := parseFlags()

	if config.TargetURL == "" {
		fmt.Fprintf(os.Stderr, "%s[!]%s Error: URL parameter required\n", ColorRed, ColorReset)
		flag.Usage()
		os.Exit(1)
	}

	scanner := NewScanner(config)
	defer scanner.PrintResults()

	fmt.Printf("%s[+]%s Target URL: %s%s%s\n", ColorGreen, ColorReset, ColorBlue, config.TargetURL, ColorReset)
	fmt.Printf("%s[+]%s Threads: %s%d%s\n", ColorGreen, ColorReset, ColorBlue, config.Threads, ColorReset)
	fmt.Printf("%s[+]%s User Agent: %s%s%s\n\n", ColorGreen, ColorReset, ColorBlue, config.UserAgent, ColorReset)

	headerChecks := createHeaderChecks(config.TargetURL)
	scanner.RunChecks(headerChecks)
}

func NewScanner(config Config) *Scanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: time.Second,
			DualStack: true,
		}).DialContext,
	}

	httpClient := &http.Client{
		Transport:     transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       15 * time.Second,
	}

	return &Scanner{
		config:     config,
		httpClient: httpClient,
	}
}

func parseFlags() Config {
	var config Config

	flag.StringVar(&config.TargetURL, "url", "", "Target URL to test")
	flag.StringVar(&config.UserAgent, "ua", defaultUserAgent, "Custom User-Agent header")
	flag.IntVar(&config.Threads, "t", runtime.NumCPU()*5, "Number of concurrent threads")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%sUsage:%s\n", ColorBold, ColorReset)
		fmt.Fprintf(os.Stderr, "  %s-url%s string  %sTarget URL to test%s\n", ColorYellow, ColorReset, ColorDim, ColorReset)
		fmt.Fprintf(os.Stderr, "  %s-ua%s string   %sCustom User-Agent (default: %s)%s\n", ColorYellow, ColorReset, ColorDim, defaultUserAgent, ColorReset)
		fmt.Fprintf(os.Stderr, "  %s-t%s int      %sConcurrent threads (default: CPU cores × 5)%s\n", ColorYellow, ColorReset, ColorDim, ColorReset)
	}

	flag.Parse()
	return config
}

func createHeaderChecks(targetURL string) []HeaderCheck {
	checks := []HeaderCheck{
		{Header: http.Header{"X-Forwarded-Host": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"X-Forwarded-For": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"X-Rewrite-Url": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"X-Host": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"User-Agent": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"Handle": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"H0st": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"Origin": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"Transfer-Encoding": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"X-Original-Url": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"X-Original-Host": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"X-Forwarded-Prefix": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"X-Amz-Server-Side-Encryption": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"X-Amz-Website-Redirect-Location": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"Trailer": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"Fastly-Ssl": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"Fastly-Host": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"Fastly-Ff": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"Fastly-Client-ip": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"Content-Type": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"Api-Version": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"AcunetiX-Header": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"Accept-Version": []string{"terajari.me"}}, Check: "terajari.me"},
		{Header: http.Header{"X-Forwarded-Proto": []string{"13377"}}, Check: ":13377"},
		{Header: http.Header{"X-Forwarded-Host": []string{"terajari.me"}, "X-Forwarded-Scheme": []string{"http"}}, Check: "terajari.me"},
	}

	for i := range checks {
		checks[i].URL = targetURL
	}

	return checks
}

func (s *Scanner) RunChecks(checks []HeaderCheck) {
	var wg sync.WaitGroup
	checksChan := make(chan HeaderCheck, s.config.Threads)

	// Start workers
	for i := 0; i < s.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for check := range checksChan {
				s.processCheck(check)
			}
		}()
	}

	// Feed checks to workers
	for _, check := range checks {
		checksChan <- check
	}
	close(checksChan)

	// Wait for all workers to finish
	wg.Wait()
}

func (s *Scanner) processCheck(check HeaderCheck) {
	reflected, err := s.checkHeaderReflected(check)
	if err != nil {
		s.mu.Lock()
		fmt.Printf("%s[✗]%s %s%s%s → %sError%s: %v\n",
			ColorRed, ColorReset,
			ColorCyan, formatHeaders(check.Header), ColorReset,
			ColorRed, ColorReset,
			err)
		s.mu.Unlock()
		return
	}

	if reflected {
		s.mu.Lock()
		s.reflectCount++
		fmt.Printf("%s[✓]%s %sReflection found%s for %s%s%s\n",
			ColorGreen, ColorReset,
			ColorGreen, ColorReset,
			ColorCyan, formatHeaders(check.Header), ColorReset)
		fmt.Printf("  %sURL%s: %s%s%s\n",
			ColorYellow, ColorReset,
			ColorBlue, check.URL, ColorReset)
		s.mu.Unlock()
	} else {
		s.mu.Lock()
		fmt.Printf("%s[✗]%s %sNo reflection%s for %s%s%s\n",
			ColorRed, ColorReset,
			ColorDim, ColorReset,
			ColorCyan, formatHeaders(check.Header), ColorReset)
		s.mu.Unlock()
	}
}

func (s *Scanner) checkHeaderReflected(check HeaderCheck) (bool, error) {
	modifiedURL, err := addCacheBuster(check.URL)
	if err != nil {
		return false, fmt.Errorf("%sURL modification error%s: %v", ColorRed, ColorReset, err)
	}

	req, err := http.NewRequest("GET", modifiedURL, nil)
	if err != nil {
		return false, fmt.Errorf("%srequest creation error%s: %v", ColorRed, ColorReset, err)
	}

	req.Header.Set("User-Agent", s.config.UserAgent)

	for key, values := range check.Header {
		for _, value := range values {
			req.Header.Set(key, value)
		}
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("%srequest failed%s: %v", ColorRed, ColorReset, err)
	}
	defer resp.Body.Close()

	if !hasCacheHeader(resp) {
		return false, nil
	}

	// Check headers first
	for _, headerValues := range resp.Header {
		for _, headerValue := range headerValues {
			if strings.Contains(headerValue, check.Check) {
				return true, nil
			}
		}
	}

	// Then check body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("%sbody read error%s: %v", ColorRed, ColorReset, err)
	}

	return strings.Contains(string(body), check.Check), nil
}

func addCacheBuster(targetURL string) (string, error) {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	randomValue := rand.Intn(9999)

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	queryParams := parsedURL.Query()
	queryParams.Set("cachebuster", fmt.Sprintf("%d", randomValue))
	parsedURL.RawQuery = queryParams.Encode()

	return parsedURL.String(), nil
}

func hasCacheHeader(resp *http.Response) bool {
	cacheHeaders := []string{
		"x-cache", "cf-cache-status", "x-drupal-cache", "x-varnish-cache", "akamai-cache-status",
		"server-timing", "x-iinfo", "x-nc", "x-hs-cf-cache-status", "x-proxy-cache",
		"x-cache-hits", "x-cache-status", "x-cache-info", "x-rack-cache", "cdn_cache_status",
		"x-akamai-cache", "x-akamai-cache-remote", "x-cache-remote", "X-Ac",
	}

	for _, header := range cacheHeaders {
		if _, ok := resp.Header[http.CanonicalHeaderKey(header)]; ok {
			return true
		}
	}
	return false
}

func formatHeaders(headers map[string][]string) string {
	var headerStrings []string
	for name, values := range headers {
		for _, value := range values {
			headerStrings = append(headerStrings, fmt.Sprintf("%s%s%s: %s%s%s",
				ColorYellow, name, ColorReset,
				ColorBlue, value, ColorReset))
		}
	}
	return strings.Join(headerStrings, ", ")
}

func (s *Scanner) PrintResults() {
	fmt.Printf("\n%s%sScan Results%s\n", ColorBold, strings.Repeat("─", 20), ColorReset)

	var resultColor string
	var status string
	if s.reflectCount > 0 {
		resultColor = ColorRed
		status = "VULNERABLE"
	} else {
		resultColor = ColorGreen
		status = "SECURE"
	}

	fmt.Printf("%sReflections Found%s: %s%d%s\n",
		ColorYellow, ColorReset,
		resultColor, s.reflectCount, ColorReset)
	fmt.Printf("%sFinal Status%s: %s%s%s\n\n",
		ColorYellow, ColorReset,
		resultColor, status, ColorReset)
}

const (
	defaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
)
