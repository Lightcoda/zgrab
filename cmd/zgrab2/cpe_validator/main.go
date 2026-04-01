package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type zgrabLine struct {
	IP   string    `json:"ip"`
	Data zgrabData `json:"data"`
}

type zgrabData struct {
	SIP zgrabSIP `json:"sip"`
}

type zgrabSIP struct {
	Status string    `json:"status"`
	Result sipResult `json:"result"`
}

type sipResult struct {
	Responses []methodResult `json:"responses"`
}

type methodResult struct {
	Fingerprint *fingerprint `json:"fingerprint,omitempty"`
}

type fingerprint struct {
	CPE string `json:"possible CPEs"`
}

type nvdSearchResponse struct {
	TotalResults int `json:"totalResults"`
}

type record struct {
	IP, CPE string
	Total   int
}

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
}

const searchURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=%s&resultsPerPage=1"

func browserGet(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json")

	return httpClient.Do(req)
}

func countCPE(cpe string) (int, error) {
	encoded := url.QueryEscape(cpe)
	reqURL := fmt.Sprintf(searchURL, encoded)

	resp, err := browserGet(reqURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// ❗ not found = ok
	if resp.StatusCode == http.StatusNotFound {
		return 0, nil
	}

	// rate limit or other issues
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}

	var s nvdSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return 0, err
	}

	return s.TotalResults, nil
}

func parseCPEs(raw string) []string {
	var out []string

	raw = strings.TrimSpace(raw)

	for _, p := range strings.Fields(raw) {
		p = strings.TrimSpace(p)

		// убрать мусорные хвосты
		p = strings.TrimRight(p, ":;, ")

		if strings.HasPrefix(p, "cpe:2.3:") {
			out = append(out, p)
		}
	}

	return out
}

func extractCPEs(line zgrabLine) []string {
	seen := make(map[string]struct{})
	var result []string

	for _, r := range line.Data.SIP.Result.Responses {
		if r.Fingerprint == nil {
			continue
		}

		for _, cpe := range parseCPEs(r.Fingerprint.CPE) {
			if _, ok := seen[cpe]; !ok {
				seen[cpe] = struct{}{}
				result = append(result, cpe)
			}
		}
	}

	return result
}

func processIP(ip string, cpes []string, rate <-chan time.Time) []record {
	if len(cpes) == 0 {
		return []record{{IP: ip, CPE: "-", Total: 0}}
	}

	var records []record

	for _, cpe := range cpes {
		<-rate

		total, err := countCPE(cpe)
		if err != nil {
			log.Printf("WARN count %s %s: %v", ip, cpe, err)
			continue
		}

		records = append(records, record{
			IP:    ip,
			CPE:   cpe,
			Total: total,
		})
	}

	return records
}

func main() {
	inputFile := flag.String("i", "-", "input file")
	outputFile := flag.String("o", "cpe_results.txt", "output file")

	// ❗ safe default (NVD is strict)
	ratePerSec := flag.Int("rate", 1, "safe NVD rate limit (recommended: 1)")
	flag.Parse()

	var in io.Reader = os.Stdin
	if *inputFile != "-" {
		f, err := os.Open(*inputFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		in = f
	}

	out, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	w := bufio.NewWriter(out)
	defer w.Flush()

	fmt.Fprintln(w, "# ip\tcpe\ttotal")

	// ❗ strict limiter (prevents 429)
	rate := time.NewTicker(time.Second / time.Duration(*ratePerSec))
	defer rate.Stop()

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	for scanner.Scan() {
		var zl zgrabLine
		if err := json.Unmarshal(scanner.Bytes(), &zl); err != nil {
			continue
		}

		if zl.Data.SIP.Status != "success" {
			continue
		}

		cpes := extractCPEs(zl)

		for _, r := range processIP(zl.IP, cpes, rate.C) {
			fmt.Fprintf(w, "%s\t%s\t%d\n", r.IP, r.CPE, r.Total)
		}

		w.Flush()

		log.Printf("INFO %s → %d CPE(s)", zl.IP, len(cpes))
	}

	if err := scanner.Err(); err != nil {
		log.Printf("ERROR: %v", err)
	}

	log.Println("DONE")
}
