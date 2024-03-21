package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Debugging HTTP Client requests with Go · Jamie Tanna | Software Engineer
// https://www.jvt.me/posts/2023/03/11/go-debug-http/
type CustomTransport struct {
	// 既存のhttp.Transportを埋め込む
	*http.Transport
}

func (s *CustomTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	httpMessageBytes, _ := httputil.DumpRequestOut(r, true)

	adjustMessage := func(message string) string {
		if !r.Context().Value(ContextKeyPrettyHttpLog).(bool) {
			message = strings.Replace(message, "\r\n", ", ", -1)
			message = strings.Replace(message, "\n", " ", -1)
		}
		return message
	}

	// Print remote IP
	r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			fmt.Printf("%s", adjustMessage(fmt.Sprintf("[RemoteAddr=%s]\n", connInfo.Conn.RemoteAddr())))
		},
	}))

	fmt.Printf("%s%s", adjustMessage(string(httpMessageBytes)), adjustMessage("\n"))
	resp, err := http.DefaultTransport.RoundTrip(r)
	respBytes, _ := httputil.DumpResponse(resp, true)
	fmt.Printf("%s\n", adjustMessage(string(respBytes)))

	return resp, err
}

const (
	DummyUsage              = "########"
	HttpContentTypeHeader   = "Content-Type"
	ContextKeyPrettyHttpLog = "ContextKeyLoggingPrettyHttpLog"
)

var (
	// Define short parameters ( this default value will be not used ).
	paramsTargetUrl         = flag.String("t", "", DummyUsage)
	paramsHttpMethod        = flag.String("m", "", DummyUsage)
	paramsRequestBody       = flag.String("r", "", DummyUsage)
	paramsHostHeader        = flag.String("hh", "", DummyUsage)
	paramsLoopCount         = flag.Int("l", 0, DummyUsage)
	paramsWaitMillSecond    = flag.Int("w", 0, DummyUsage)
	paramsPrettyHttpMessage = flag.Bool("p", false, DummyUsage)
	paramsHelp              = flag.Bool("h", false, DummyUsage)

	// HTTP Header templates
	httpHeaderEmptyMap        = make(map[string]string, 0)
	httpHeaderContentTypeForm = map[string]string{HttpContentTypeHeader: "application/x-www-form-urlencoded;charset=utf-8"}
	httpHeaderContentTypeJson = map[string]string{HttpContentTypeHeader: "application/json;charset=utf-8"}
)

func init() {
	// Define long parameters
	flag.StringVar(paramsTargetUrl /*       */, "target-host" /*         */, "" /*     */, "[required] Target URL ( sample: https://www.****.**/***/*** )")
	flag.StringVar(paramsHttpMethod /*      */, "m-http-method" /*       */, "GET" /*  */, "[optional] HTTP method")
	flag.StringVar(paramsRequestBody /*     */, "request-body" /*        */, "" /*     */, "[optional] Request body")
	flag.StringVar(paramsHostHeader /*      */, "host-header" /*         */, "" /*     */, "[optional] Host header")
	flag.IntVar(paramsLoopCount /*          */, "loop-count" /*          */, 3 /*      */, "[optional] Loop count")
	flag.IntVar(paramsWaitMillSecond /*     */, "wait-millisecond" /*    */, 1000 /*   */, "[optional] Wait millisecond")
	flag.BoolVar(paramsPrettyHttpMessage /* */, "pretty-http-message" /* */, false /*  */, "[optional] Print pretty http message")
	flag.BoolVar(paramsHelp /*              */, "help" /*                */, false /*  */, "help")
}

func main() {

	// Set adjusted usage
	b := new(bytes.Buffer)
	flag.CommandLine.SetOutput(b)
	flag.Usage()
	re := regexp.MustCompile("(-\\S+)( *\\S*)+\n*\\s+" + DummyUsage + "\n*\\s+(-\\S+)( *\\S*)+\n")
	usage := re.ReplaceAllString(b.String(), "  $1, -$3$4\n")
	flag.CommandLine.SetOutput(os.Stderr)
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), usage)
	}

	flag.Parse()
	if *paramsHelp || *paramsTargetUrl == "" {
		flag.Usage()
		os.Exit(0)
	}

	// Set SSLKEYLOGFILE file path
	sslKeyLogFile := os.Getenv("SSLKEYLOGFILE")
	if sslKeyLogFile == "" {
		sslKeyLogFile = os.TempDir() + "/ssl_key_log_file_" + createUuid()
	}

	client := http.Client{
		Transport: CreateCustomTransport(sslKeyLogFile),
	}

	fmt.Println("#--------------------")
	fmt.Println("# Command information")
	fmt.Println("#--------------------")
	fmt.Printf("Target URL      : %s\n", *paramsTargetUrl)
	fmt.Printf("HTTP Method     : %s\n", *paramsHttpMethod)
	fmt.Printf("Request body    : %s\n", *paramsRequestBody)
	fmt.Printf("Host header     : %s\n", *paramsHostHeader)
	fmt.Printf("Loop count      : %d\n", *paramsLoopCount)
	fmt.Printf("Wait millsecond : %d\n", *paramsWaitMillSecond)
	fmt.Printf("SSLKEYLOGFILE   : %s\n", sslKeyLogFile)

	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyPrettyHttpLog, *paramsPrettyHttpMessage)

	for i := 0; i < *paramsLoopCount; i++ {
		//"https://httpbin.org/post"
		// {"name":"taro", "age":20}
		_, _ = DoHttpRequest(ctx, client, *paramsHttpMethod, *paramsTargetUrl, httpHeaderContentTypeJson, *paramsRequestBody)

		//resp, err := DoHttpRequest(ctx, client, *paramsHttpMethod, *paramsTargetUrl, httpHeaderContentTypeJson, *paramsRequestBody)
		//body := handleResponse(resp, err)
		//jsonBody := ToJsonObject(body)
		//fmt.Printf("headers.X-Amzn-Trace-Id => %v\n", Get(jsonBody, "headers.X-Amzn-Trace-Id"))

		time.Sleep(time.Duration(*paramsWaitMillSecond) * time.Millisecond)
	}
}

// =======================================
// HTTP Utils
// =======================================

func CreateCustomTransport(sslKeyLogFile string) *CustomTransport {
	customTr := &CustomTransport{Transport: http.DefaultTransport.(*http.Transport).Clone()}
	f, err := os.OpenFile(sslKeyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	handleError(err)
	defer f.Close()
	customTr.TLSClientConfig = &tls.Config{
		KeyLogWriter: f,
	}
	return customTr
}

func DoHttpRequest(ctx context.Context, client http.Client, method string, url string, headers map[string]string, body string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
	handleError(err)
	return client.Do(req)
}

func handleResponse(resp *http.Response, err error) []byte {
	handleError(err)
	responseBodyBytes, err := io.ReadAll(resp.Body)
	handleError(err)
	return responseBodyBytes
}

// =======================================
// Json Utils
// =======================================

// ToJsonObject json bytes to interface{} object
func ToJsonObject(body []byte) interface{} {
	var jsonObject interface{}
	err := json.Unmarshal(body, &jsonObject)
	handleError(err)
	return jsonObject
}

// Get get value in interface{} object [ example : object["aaa"][0]["bbb"] -> keyChain: "aaa.0.bbb" ]
func Get(object interface{}, keyChain string) interface{} {
	keys := strings.Split(keyChain, ".")
	var result interface{}
	var exists bool
	for _, key := range keys {
		exists = false
		if _, ok := object.(map[string]interface{}); ok {
			exists = true
			object = object.(map[string]interface{})[key]
			result = object
			continue
		}
		if values, ok := object.([]interface{}); ok {
			for i, v := range values {
				if strconv.FormatInt(int64(i), 10) == key {
					exists = true
					object = v
					result = object
					continue
				}
			}
		}
	}
	if exists {
		return result
	}
	return nil
}

// ToMap to map
func ToMap(v interface{}, keys []string) map[string]interface{} {
	resultMap := make(map[string]interface{}, len(keys))
	for _, key := range keys {
		resultMap[key] = Get(v, key)
	}
	return resultMap
}

// ToJsonString to json string
func ToJsonString(v interface{}) string {
	result, _ := json.Marshal(v)
	return string(result)
}

// =======================================
// Common Utils
// =======================================

func createUuid() string {
	seed := strconv.FormatInt(time.Now().UnixNano(), 10)
	shaBytes := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(shaBytes[:])
}

func handleError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
