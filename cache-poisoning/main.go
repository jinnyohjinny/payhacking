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

const (
	defaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
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
	config := parseFlags()

	if config.TargetURL == "" {
		fmt.Fprintln(os.Stderr, "Error: diperlukan parameter -url")
		flag.Usage()
		os.Exit(1)
	}

	scanner := NewScanner(config)
	defer scanner.PrintResults()

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
	}

	return &Scanner{
		config:     config,
		httpClient: httpClient,
	}
}

func parseFlags() Config {
	var config Config

	flag.StringVar(&config.TargetURL, "url", "", "Url untuk diuji")
	flag.StringVar(&config.UserAgent, "ua", defaultUserAgent, "User Agent Header")
	flag.IntVar(&config.Threads, "t", runtime.NumCPU()*5, "Number of Threads")

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

	// Set URL for all checks
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
		return
	}

	if reflected {
		s.mu.Lock()
		s.reflectCount++
		fmt.Printf("\n%s", colorize(fmt.Sprintf("Headers reflected: [%v]", formatHeaders(check.Header)), "9"))
		fmt.Printf("%s", "\n"+check.URL+"\n")
		s.mu.Unlock()
	}
}

func (s *Scanner) checkHeaderReflected(check HeaderCheck) (bool, error) {
	modifiedURL, err := addCacheBuster(check.URL)
	if err != nil {
		fmt.Println("Error modifying URL:", err)
		return false, err
	}

	req, err := http.NewRequest("GET", modifiedURL, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("User-Agent", s.config.UserAgent)

	for key, values := range check.Header {
		for _, value := range values {
			req.Header.Set(key, value)
		}
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false, err
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
		return false, err
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
			headerStrings = append(headerStrings, fmt.Sprintf("%s: %s", name, value))
		}
	}
	return strings.Join(headerStrings, ", ")
}

func colorize(text, color string) string {
	return "\033[38;5;" + color + "m" + text + "\033[0m"
}

func (s *Scanner) PrintResults() {
	fmt.Printf("\n🚨 Number of Reflections Found: %s\n", colorize(fmt.Sprintf("%v", s.reflectCount), "80"))
}
