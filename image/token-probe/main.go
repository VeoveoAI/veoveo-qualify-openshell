// Command token-probe requests Docker Hub's anonymous pull token with Go's net/http and
// crypto/tls, the stack buildctl fetches a registry token with when BuildKit asks it for
// one, then sends two requests a GET /token rule refuses. It prints one JSON report and
// never the token.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"os"
	"time"
)

type result struct {
	Status int    `json:"status"`
	Token  bool   `json:"token"`
	Body   string `json:"body,omitempty"`
	Error  string `json:"error,omitempty"`
	Ms     int64  `json:"ms"`
}

func fetch(client *http.Client, method, url string) (r result) {
	start := time.Now()
	defer func() { r.Ms = time.Since(start).Milliseconds() }()
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	response, err := client.Do(request)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	r.Status = response.StatusCode
	var token struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(body, &token) == nil && (token.Token != "" || token.AccessToken != "") {
		r.Token = true
	} else if len(body) > 200 {
		r.Body = string(body[:200])
	} else {
		r.Body = string(body)
	}
	return r
}

func main() {
	base := flag.String("base", "https://auth.docker.io", "the token service")
	repository := flag.String("repository", "library/hello-world", "the repository the token is scoped to")
	flag.Parse()
	client := &http.Client{Timeout: 30 * time.Second}
	token := *base + "/token?service=registry.docker.io&scope=repository:" + *repository + ":pull"
	report := map[string]result{
		"token":     fetch(client, http.MethodGet, token),
		"post":      fetch(client, http.MethodPost, token),
		"otherPath": fetch(client, http.MethodGet, *base+"/v2/"),
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		os.Exit(1)
	}
}
