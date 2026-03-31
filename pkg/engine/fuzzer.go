package engine

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vulnerability-scanner/pkg/crawler"
	"vulnerability-scanner/pkg/reporter"
)

var sqlPayloads = []string{"'", "''", "`", "' OR 1=1--"}
var xssPayloads = []string{"<script>alert('XSS')</script>", "\"><svg/onload=alert(1)>"}
var sqlErrors = []string{
	"you have an error in your sql syntax",
	"warning: mysql",
	"unclosed quotation mark after the character string",
	"quoted string not properly terminated",
	"pg_query(): query failed",
}

func FuzzURL(target string, rep *reporter.Reporter) {
	parsedURL, err := url.Parse(target)
	if err != nil || len(parsedURL.Query()) == 0 {
		return
	}

	queryMap := parsedURL.Query()
	for param := range queryMap {
		for _, payload := range sqlPayloads {
			testVulnerability(parsedURL, param, payload, "SQLi", rep)
		}
		for _, payload := range xssPayloads {
			testVulnerability(parsedURL, param, payload, "XSS", rep)
		}
	}
}

func testVulnerability(parsedURL *url.URL, param, payload, vulnType string, rep *reporter.Reporter) {
	queryMap := parsedURL.Query()
	queryMap.Set(param, payload)
	parsedURL.RawQuery = queryMap.Encode()
	testURL := parsedURL.String()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	body := strings.ToLower(string(bodyBytes))
	analyzeResponse(testURL, payload, body, vulnType, rep)
}

func FuzzForm(form crawler.Form, rep *reporter.Reporter) {
	if form.Method != "POST" || form.Action == "" {
		return
	}

	for targetInput := range form.Inputs {
		for _, payload := range sqlPayloads {
			testFormVulnerability(form, targetInput, payload, "SQLi", rep)
		}
		for _, payload := range xssPayloads {
			testFormVulnerability(form, targetInput, payload, "XSS", rep)
		}
	}
}

func testFormVulnerability(form crawler.Form, targetInput, payload, vulnType string, rep *reporter.Reporter) {
	data := url.Values{}
	for k, v := range form.Inputs {
		if k == targetInput {
			data.Set(k, payload)
		} else {
			data.Set(k, v)
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("POST", form.Action, strings.NewReader(data.Encode()))
	if err != nil {
		return
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	body := strings.ToLower(string(bodyBytes))
	analyzeResponse(form.Action, payload, body, vulnType, rep)
}

func analyzeResponse(testURL, payload, body, vulnType string, rep *reporter.Reporter) {
	if vulnType == "SQLi" {
		for _, sqlErr := range sqlErrors {
			if strings.Contains(body, sqlErr) {
				fmt.Printf("[!!!] ZAAFİYET (SQLi): %s \n", testURL)
				rep.AddFinding(testURL, "SQLi", payload)
				return
			}
		}
	}

	if vulnType == "XSS" {
		if strings.Contains(body, strings.ToLower(payload)) {
			fmt.Printf("[!!!] ZAAFİYET (XSS): %s \n", testURL)
			rep.AddFinding(testURL, "XSS", payload)
			return
		}
	}
}
