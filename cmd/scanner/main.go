package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"vulnerability-scanner/pkg/crawler"
	"vulnerability-scanner/pkg/engine"
	"vulnerability-scanner/pkg/reporter"

	"golang.org/x/time/rate"
)

type Config struct {
	TargetURL   string
	Concurrency int
	RateLimit   int
	Cookie      string
	AuthHeader  string
	OutputFile  string
}

func main() {
	var cfg Config
	flag.StringVar(&cfg.TargetURL, "u", "", "")
	flag.IntVar(&cfg.Concurrency, "t", 10, "")
	flag.IntVar(&cfg.RateLimit, "rl", 20, "")
	flag.StringVar(&cfg.Cookie, "cookie", "", "")
	flag.StringVar(&cfg.AuthHeader, "header", "", "")
	flag.StringVar(&cfg.OutputFile, "o", "rapor.json", "")
	flag.Parse()

	if cfg.TargetURL == "" {
		log.Fatal("Kullanım: scanner -u http://hedef.com")
	}

	limiter := rate.NewLimiter(rate.Limit(cfg.RateLimit), 1)
	urlsToCrawl := make(chan string, 1000)
	var wg sync.WaitGroup
	visited := make(map[string]bool)
	var visitedMutex sync.RWMutex
	rep := reporter.NewReporter()

	for i := 1; i <= cfg.Concurrency; i++ {
		wg.Add(1)
		go worker(i, &cfg, urlsToCrawl, &wg, limiter, visited, &visitedMutex, rep)
	}

	urlsToCrawl <- cfg.TargetURL

	time.Sleep(2 * time.Second)

	close(urlsToCrawl)
	wg.Wait()

	rep.ExportJSON(cfg.OutputFile)
	fmt.Printf("[*] Tarama bitti. Rapor kaydedildi: %s\n", cfg.OutputFile)
}

func worker(id int, cfg *Config, urlsToCrawl chan string, wg *sync.WaitGroup, limiter *rate.Limiter, visited map[string]bool, visitedMutex *sync.RWMutex, rep *reporter.Reporter) {
	defer wg.Done()

	for url := range urlsToCrawl {
		limiter.Wait(context.Background())

		visitedMutex.RLock()
		isVisited := visited[url]
		visitedMutex.RUnlock()

		if isVisited {
			continue
		}

		visitedMutex.Lock()
		visited[url] = true
		visitedMutex.Unlock()

		bodyReader, err := fetchURL(id, url, cfg)
		if err != nil {
			continue
		}

		bodyBytes, err := io.ReadAll(bodyReader)
		bodyReader.Close()
		if err != nil {
			continue
		}

		engine.FuzzURL(url, rep)

		forms := crawler.ExtractForms(bytes.NewReader(bodyBytes), url)
		for _, form := range forms {
			engine.FuzzForm(form, rep)
		}

		newLinks := crawler.ExtractLinks(bytes.NewReader(bodyBytes), url)

		for _, link := range newLinks {
			visitedMutex.RLock()
			alreadyVisited := visited[link]
			visitedMutex.RUnlock()

			if !alreadyVisited {
				urlsToCrawl <- link
			}
		}
	}
}

func fetchURL(workerID int, target string, cfg *Config) (io.ReadCloser, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 ProScanner/1.0")

	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}

	if cfg.AuthHeader != "" {
		req.Header.Add("Custom-Auth", cfg.AuthHeader)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}
