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

func main() {
	url := flag.String("url", "https://example.com", "url target")
	flag.Parse()

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

	req, err := http.NewRequest("GET", *url, nil)
	if err != nil {
		fmt.Println("Error membuat request:", err)
		return
	}

	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error melakukan request:", err)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error membaca body:", err)
		return
	}
	originalBody := string(bodyBytes)
	originalStatus := resp.Status
	originalHeaders := resp.Header

	protocol := resp.Proto
	fmt.Println("Protocol:", protocol)
	fmt.Println("Status Code:", resp.Status)

	for header := range resp.Header {
		fmt.Println("\nTesting Header:", header+":")

		if protocol == "HTTP/2.0" && !isValidHopByHopHeader(header) {
			fmt.Println("⚠ Skipping invalid Connection header for HTTP/2:", header)
			continue
		}

		req, err := http.NewRequest("GET", *url, nil)
		if err != nil {
			fmt.Println("Error membuat request:", err)
			return
		}

		req.Header.Set("Connection", header) // Set header Connection ke header saat ini
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		hopResp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}
		defer hopResp.Body.Close()

		hopBodyBytes, err := io.ReadAll(hopResp.Body)
		if err != nil {
			fmt.Println("Error membaca hop-by-hop body:", err)
			continue
		}
		hopBody := string(hopBodyBytes)

		// Bandingkan Status Code
		if originalStatus != hopResp.Status {
			fmt.Printf("🚨 Status Code Berbeda! Original=%s, Modified=%s\n", originalStatus, hopResp.Status)
		}

		// Bandingkan Body
		if originalBody != hopBody {
			fmt.Println("🚨 Body Berbeda!")
			fmt.Println("Original Body Length:", len(originalBody))
			fmt.Println("Modified Body Length:", len(hopBody))
		}

		headersEqual, diff := compareHeaders(originalHeaders, hopResp.Header)
		if !headersEqual {
			fmt.Println("🚨 Header Berbeda!")
			fmt.Println("Perbedaan:")
			for _, d := range diff {
				fmt.Println(" -", d)
			}
		}

		// Jika SEMUA sama, berarti tidak ada perubahan
		if originalStatus == hopResp.Status && originalBody == hopBody && headersEqual {
			fmt.Println("✅ Tidak ada perubahan (aman)")
		}
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
			differences = append(differences, fmt.Sprintf("Header '%s' hilang di respons baru", key))
			continue
		}

		if len(values) != len(newValues) {
			differences = append(differences, fmt.Sprintf("Jumlah nilai header '%s' berbeda: %d vs %d", key, len(values), len(newValues)))
			continue
		}

		for i := range values {
			if strings.TrimSpace(values[i]) != strings.TrimSpace(newValues[i]) {
				differences = append(differences, fmt.Sprintf("Nilai header '%s' berbeda: '%s' vs '%s'", key, values[i], newValues[i]))
			}
		}
	}

	// Cek header baru yang tidak ada di original
	for key := range new {
		if ignoreHeaders[key] {
			continue
		}

		if _, exists := original[key]; !exists {
			differences = append(differences, fmt.Sprintf("Header baru '%s' muncul di respons baru", key))
		}
	}

	return len(differences) == 0, differences
}
