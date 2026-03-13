package main

import (
	"flag"
	"fmt"
	"io"
	stdhttp "net/http"
	"os"
	"strings"

	stackhttp "github.com/0xh7/lex-internet/pkg/http"
)

type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func main() {
	method := flag.String("X", "", "request method")
	body := flag.String("d", "", "request body")
	bodyFile := flag.String("data-file", "", "path to request body file")
	output := flag.String("o", "", "write response body to file")
	verbose := flag.Bool("v", false, "show response metadata")
	follow := flag.Bool("L", false, "follow redirects")
	var headers headerFlags
	flag.Var(&headers, "H", "custom header in the form Key: Value")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: http-client [flags] <url>")
		os.Exit(1)
	}

	url := flag.Arg(0)
	data := []byte(*body)
	if *bodyFile != "" {
		fileData, err := os.ReadFile(*bodyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "http-client: read %s: %v\n", *bodyFile, err)
			os.Exit(1)
		}
		data = fileData
	}

	if strings.TrimSpace(*method) == "" {
		if len(data) > 0 {
			*method = "POST"
		} else {
			*method = "GET"
		}
	}

	if strings.HasPrefix(strings.ToLower(url), "https://") {
		if err := doHTTPS(strings.ToUpper(*method), url, headers, data, *output, *verbose, *follow); err != nil {
			fmt.Fprintf(os.Stderr, "http-client: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := doHTTP(strings.ToUpper(*method), url, headers, data, *output, *verbose, *follow); err != nil {
		fmt.Fprintf(os.Stderr, "http-client: %v\n", err)
		os.Exit(1)
	}
}

func doHTTP(method, url string, headers headerFlags, body []byte, output string, verbose, follow bool) error {
	client := stackhttp.NewClient()
	client.FollowRedirects = follow

	req, err := stackhttp.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	for _, header := range headers {
		key, value, ok := strings.Cut(header, ":")
		if !ok {
			return fmt.Errorf("malformed header %q", header)
		}
		req.SetHeader(strings.TrimSpace(key), strings.TrimSpace(value))
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()

	if verbose {
		fmt.Printf("%s %d %s\n", resp.Version, resp.StatusCode, resp.StatusText)
		for key, values := range resp.Headers {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
		fmt.Println()
	}

	return writeBody(resp.Body, output)
}

func doHTTPS(method, url string, headers headerFlags, body []byte, output string, verbose, follow bool) error {
	var payload io.Reader
	if len(body) > 0 {
		payload = strings.NewReader(string(body))
	}

	req, err := stdhttp.NewRequest(method, url, payload)
	if err != nil {
		return err
	}
	for _, header := range headers {
		key, value, ok := strings.Cut(header, ":")
		if !ok {
			return fmt.Errorf("malformed header %q", header)
		}
		req.Header.Add(strings.TrimSpace(key), strings.TrimSpace(value))
	}

	client := &stdhttp.Client{}
	if !follow {
		client.CheckRedirect = func(*stdhttp.Request, []*stdhttp.Request) error {
			return stdhttp.ErrUseLastResponse
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if verbose {
		fmt.Printf("%s %s\n", resp.Proto, resp.Status)
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
		fmt.Println()
	}

	return writeBody(data, output)
}

func writeBody(body []byte, output string) error {
	if output == "" {
		_, err := os.Stdout.Write(body)
		return err
	}
	return os.WriteFile(output, body, 0644)
}
