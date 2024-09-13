package opnsense

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ClientOpts specifies the options of the clients.
type ClientOpts struct {
	Endpoint  string
	ApiKey    string
	ApiSecret string
	Timeout   int32
	Insecure  bool
}

// Client implements an API client for the OPNsense API.
type Client struct {
	httpClient *http.Client
	endpoint   *url.URL
	apiKey     string
	apiSecret  string
}

// isSupportedHttpMethod checks if the supplied method is a supported HTTP method.
func isSupportedHttpMethod(method string) bool {
	validMethods := []string{
		"GET",
		"POST",
	}

	for _, m := range validMethods {
		if strings.ToUpper(method) == m {
			return true
		}
	}
	return false
}

// NewClient creates and initialises a client instance.
func NewClient(opts ClientOpts) (*Client, error) {
	apiEndpoint, err := url.ParseRequestURI(strings.Trim(opts.Endpoint, "/") + "/api/")
	if err != nil {
		return nil, errors.New("API endpoint is invalid. It should be in the format `https://<your-opnsense-instance>`. Do not include the `/api` suffix")
	}

	if len(opts.ApiKey) <= 0 {
		return nil, errors.New("API key must not be nil")
	}

	if len(opts.ApiSecret) <= 0 {
		return nil, errors.New("API secret must not be nil")
	}

	var transport http.RoundTripper = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure,
		},
	}

	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(opts.Timeout) * time.Second,
		},
		endpoint:  apiEndpoint,
		apiKey:    opts.ApiKey,
		apiSecret: opts.ApiSecret,
	}, nil
}

// DoRequest performs a HTTP request against the client's OPNsense API endpoint.
func (c *Client) DoRequest(method string, path string, reqBody []byte) (*http.Response, error) {
	if !isSupportedHttpMethod(method) {
		return nil, fmt.Errorf("%s is not a currently supported method", method)
	}

	// Remove unnecessary slashes in path
	path = strings.Trim(path, "/")

	// Create OPNsense API url
	reqUrl := c.endpoint.String() + path

	// Create http request for the OPNsense API
	req, err := http.NewRequest(method, reqUrl, bytes.NewReader(reqBody))
	if err != nil {
		return nil, errors.New("Unable to create http request for the OPNsense API. Error: " + err.Error())
	}

	// Add headers
	if method == http.MethodPost {
		req.Header.Set("content-type", "application/json; charset=UTF-8")
	}

	// Set authentication parameters for http request
	req.SetBasicAuth(c.apiKey, c.apiSecret)

	// Perform http request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.New("Failed to perform http request to the OPNsense API. Error: " + err.Error())
	}

	if resp.StatusCode == 403 {
		return nil, errors.New("Unable to authenticate with the OPNsense API. Ensure that your credentials are valid and has the required privileges.")
	}

	return resp, nil
}
