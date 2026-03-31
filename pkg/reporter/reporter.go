package reporter

import (
	"encoding/json"
	"os"
	"sync"
)

type Vulnerability struct {
	URL     string `json:"url"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

type Reporter struct {
	mu       sync.Mutex
	Findings []Vulnerability
}

func NewReporter() *Reporter {
	return &Reporter{
		Findings: make([]Vulnerability, 0),
	}
}

func (r *Reporter) AddFinding(url, vulnType, payload string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.Findings = append(r.Findings, Vulnerability{
		URL:     url,
		Type:    vulnType,
		Payload: payload,
	})
}

func (r *Reporter) ExportJSON(filename string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := json.MarshalIndent(r.Findings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}
