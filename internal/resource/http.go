// Copyright 2016 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resource

import (
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/coreos/ignition/config/types"
	"github.com/coreos/ignition/internal/log"
	"github.com/coreos/ignition/internal/version"

	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
)

const (
	initialBackoff = 100 * time.Millisecond
	maxBackoff     = 5 * time.Second

	defaultHttpResponseHeaderTimeout = 10
	defaultHttpTotalTimeout          = 0
)

var (
	ErrTimeout = errors.New("unable to fetch resource in time")
)

// HttpClient is a simple wrapper around the Go HTTP client that standardizes
// the process and logging of fetching payloads.
type HttpClient struct {
	client  *http.Client
	logger  *log.Logger
	timeout time.Duration
	// returnThreshold is the value that causes the retry logic to end when an
	// HTTP status code is acquired below this
	returnThreshold int
}

// NewHttpClient creates a new client with the given logger, timeouts, and returnThreshold.
// If the returnThreshold is 0, a default value of 500 is used. HTTP status
// codes below this value cause the retry logic to end.
func NewHttpClient(logger *log.Logger, timeouts types.Timeouts, returnThreshold int) HttpClient {
	responseHeader := defaultHttpResponseHeaderTimeout
	total := defaultHttpTotalTimeout
	if timeouts.HTTPResponseHeaders != nil {
		responseHeader = *timeouts.HTTPResponseHeaders
	}
	if timeouts.HTTPTotal != nil {
		total = *timeouts.HTTPTotal
	}
	if returnThreshold == 0 {
		returnThreshold = 500
	}
	return HttpClient{
		client: &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: time.Duration(responseHeader) * time.Second,
				Dial: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).Dial,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
		logger:          logger,
		timeout:         time.Duration(total) * time.Second,
		returnThreshold: returnThreshold,
	}
}

// Get performs an HTTP GET on the provided URL with the provided request header
// and returns the response body Reader, HTTP status code, and error (if any). By
// default, User-Agent is added to the header but this can be overridden.
func (c HttpClient) Get(url string, header http.Header) (io.ReadCloser, int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	return c.performRequestWithHeader(req, header)
}

// Post performs an HTTP POST on the provided URL with the provided request header
// and returns the response body Reader, HTTP status code, and error (if any). By
// default, User-Agent is added to the header but this can be overridden.
func (c HttpClient) Post(url string, header http.Header, body io.Reader) (io.ReadCloser, int, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, 0, err
	}
	return c.performRequestWithHeader(req, header)
}

func (c HttpClient) performRequestWithHeader(req *http.Request, header http.Header) (io.ReadCloser, int, error) {
	req.Header.Set("User-Agent", "Ignition/"+version.Raw)

	for key, values := range header {
		req.Header.Del(key)
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	return c.performRequest(req)
}

func (c HttpClient) performRequest(req *http.Request) (io.ReadCloser, int, error) {
	ctx := context.Background()
	if c.timeout != 0 {
		ctx, _ = context.WithTimeout(ctx, c.timeout)
	}

	duration := initialBackoff
	for attempt := 1; ; attempt++ {
		c.logger.Debug("GET %s: attempt #%d", req.URL, attempt)
		resp, err := ctxhttp.Do(ctx, c.client, req)

		if err == nil {
			c.logger.Debug("GET result: %s", http.StatusText(resp.StatusCode))
			if resp.StatusCode < c.returnThreshold {
				return resp.Body, resp.StatusCode, nil
			}
			resp.Body.Close()
		} else {
			c.logger.Debug("GET error: %v", err)
		}

		duration = duration * 2
		if duration > maxBackoff {
			duration = maxBackoff
		}

		// Wait before next attempt or exit if we timeout while waiting
		select {
		case <-time.After(duration):
		case <-ctx.Done():
			return nil, 0, ErrTimeout
		}
	}
}
