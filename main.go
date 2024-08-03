package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type Result struct {
	URL           string
	Header        string
	StatusCode    int
	ContentLength int64
	Body          string
}

func main() {
	urlPtr := flag.String("url", "", "URL to make requests to")
	headersFilePtr := flag.String("headers", "", "File containing headers for requests")
	proxyPtr := flag.String("proxy", "", "Proxy server IP:PORT (e.g., 127.0.0.1:8080)")
	requestCatcherURL := flag.String("catcher", "", "URL of the Request Catcher to verify XSS execution")
	outputFilePtr := flag.String("output", "xss_results.txt", "File to save XSS detection results")
	quietPtr := flag.Bool("q", false, "Suppress banner")
	flag.Parse()
	log.SetFlags(0)

	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	// Print tool banner
	if !*quietPtr {
		fmt.Println(yellow(`
			`) + red(` __`) + yellow(`               `) + red(` __`) + yellow(`                      
		`) + green(`/ /  ___ ___  ___/ /__ _______ _    _____ 
	 `) + blue(`/ _ \/ -_) _ \/ _  / -_) __/ _ \ |/|/ / _ \
	`)+ magenta(`/_//_/\__/\_,_/\_,_/\__/_/ / .__/__,__/_//_/
		`) + cyan(`TRHACKNON       /_/               
	`))
	}

	if *urlPtr == "" {
		fmt.Println("Please provide a valid URL using the -url flag")
		return
	}

	if *headersFilePtr == "" {
		fmt.Println("Please provide a valid headers file using the -headers flag")
		return
	}

	if *requestCatcherURL == "" {
		fmt.Println("Please provide a valid Request Catcher URL using the -catcher flag")
		return
	}

	headers, err := readHeadersFromFile(*headersFilePtr)
	if err != nil {
		fmt.Println("Error reading headers:", err)
		return
	}

	// Create variations of XSS payloads
	variationHeaders := []string{}
	for _, header := range headers {
		variationHeaders = append(variationHeaders, header)
		// Adding variations with `>`, `'>`, and other characters
		variationHeaders = append(variationHeaders,
			strings.ReplaceAll(header, "<script", `"><script`),
			strings.ReplaceAll(header, "<script", `'><script`),
		)
	}

	var wg sync.WaitGroup
	results := make(chan Result)

	for _, header := range variationHeaders {
		wg.Add(1)
		go func(header string) {
			defer wg.Done()

			response, body, err := makeRequest(*urlPtr, header, *proxyPtr)
			if err != nil {
				return
			}

			result := Result{
				URL:           *urlPtr + "?cachebuster=" + generateCacheBuster(),
				Header:        header,
				StatusCode:    response.StatusCode,
				ContentLength: response.ContentLength,
				Body:          body,
			}
			results <- result
		}(header)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	outputFile, err := os.Create(*outputFilePtr)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer outputFile.Close()

	printResults(results, *requestCatcherURL, outputFile)
}

func readHeadersFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	headers := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		headers = append(headers, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return headers, nil
}

func makeRequest(baseURL, header, proxy string) (*http.Response, string, error) {
	urlWithBuster := baseURL + "?cachebuster=" + generateCacheBuster()
	headers := parseHeaders(header)

	req, err := http.NewRequest("GET", urlWithBuster, nil)
	if err != nil {
		return nil, "", err
	}

	for _, h := range headers {
		parts := strings.SplitN(h, ": ", 2)
		if len(parts) == 2 {
			req.Header.Add(parts[0], parts[1])
		}
	}

	client := &http.Client{}
	if proxy != "" {
		proxyURL, err := url.Parse("http://" + proxy)
		if err != nil {
			fmt.Println("Error parsing proxy URL:", err)
			return nil, "", err
		}
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		client = &http.Client{Transport: transport}
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, "", err
	}

	return response, string(bodyBytes), nil
}

func parseHeaders(header string) []string {
	return strings.Split(header, "\n")
}

func generateCacheBuster() string {
	rand.Seed(time.Now().UnixNano())
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func printResults(results <-chan Result, requestCatcherURL string, outputFile *os.File) {
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	for result := range results {
		statusColorFunc := red
		if result.StatusCode == 200 {
			statusColorFunc = green
		}

		statusOutput := statusColorFunc(fmt.Sprintf("[%d]", result.StatusCode))
		contentLengthOutput := magenta(fmt.Sprintf("[CL: %d]", result.ContentLength))
		headerOutput := cyan(fmt.Sprintf("[%s]", result.Header))

		parsedURL, _ := url.Parse(result.URL)
		query := parsedURL.Query()
		query.Del("cachebuster")
		parsedURL.RawQuery = query.Encode()
		urlOutput := yellow(fmt.Sprintf("[%s]", parsedURL.String()))

		resultOutput := fmt.Sprintf("%s %s %s %s", statusOutput, contentLengthOutput, headerOutput, urlOutput)
		fmt.Println(resultOutput)

		if detectXSS(requestCatcherURL) {
			xssDetected := fmt.Sprintf("Potential XSS detected with header: %s\n", result.Header)
			fmt.Println(red(xssDetected))
			outputFile.WriteString(xssDetected)
		}
	}
}

func detectXSS(requestCatcherURL string) bool {
	resp, err := http.Get(requestCatcherURL + "/__xss_detected__")
	if err != nil {
		fmt.Println("Error checking Request Catcher:", err)
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return false
	}

	bodyStr := string(bodyBytes)
	return strings.Contains(bodyStr, "xss_detected")
}
