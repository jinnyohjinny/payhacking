package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func main() {
	url := "https://jatengprov.go.id"

	customTransport := &http.Transport{
		ForceAttemptHTTP2: false, // Matikan HTTP/2 jika bisa
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: customTransport,
		Timeout:   10 * time.Second,
	}

	// Melakukan request GET awal
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Tambahkan header "Connection: close" untuk mencoba HTTP/1.1
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	// Membaca isi respons awal
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error membaca body:", err)
		return
	}
	originalBody := string(bodyBytes)

	// Cek versi HTTP yang digunakan
	protocol := resp.Proto

	for header := range resp.Header {
		fmt.Println(header + ":")

		if protocol == "HTTP/2.0" && !isValidHopByHopHeader(header) {
			fmt.Println("Skipping invalid Connection header for HTTP/2:", header)
			continue
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		req.Header.Set("Connection", header)

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

		if resp.Status != hopResp.Status || originalBody != hopBody {
			fmt.Println("Hop-by-hop abuse detected!")
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
