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
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DummyUsage                 = "########"
	HttpContentTypeHeader      = "Content-Type"
	ContextKeyPrettyHttpLog    = "ContextKeyLoggingPrettyHttpLog"
	ContextKeyNoOutputResponse = "ContextKeyNoOutputResponse"
	TimeFormat                 = "2006-01-02 15:04:05.9999 [MST]"
)

var (
	// Define short parameters ( this default value will be not used ).
	paramsTargetUrl           = flag.String("t", "", DummyUsage)
	paramsHttpMethod          = flag.String("m", "", DummyUsage)
	paramsBody                = flag.String("b", "", DummyUsage)
	paramsHostHeader          = flag.String("hh", "", DummyUsage)
	paramsUuidHeaderName      = flag.String("uh", "", DummyUsage)
	paramsLoopCount           = flag.Int("l", 0, DummyUsage)
	paramsWaitMillSecond      = flag.Int("w", 0, DummyUsage)
	paramsPrettyHttpMessage   = flag.Bool("p", false, DummyUsage)
	paramsNoOutputResponse    = flag.Bool("n", false, DummyUsage)
	paramsSkipTlsVerification = flag.Bool("sk", false, DummyUsage)
	paramsHelp                = flag.Bool("h", false, DummyUsage)

	// HTTP Header templates
	httpHeaderEmptyMap        = make(map[string]string, 0)
	httpHeaderContentTypeForm = map[string]string{HttpContentTypeHeader: "application/x-www-form-urlencoded;charset=utf-8"}
	httpHeaderContentTypeJson = map[string]string{HttpContentTypeHeader: "application/json;charset=utf-8"}
)

func init() {
	// Define long parameters
	flag.StringVar(paramsTargetUrl /*         */, "target-host" /*           */, "" /*     */, "[required] Target URL ( sample: https://www.****.**/***/*** )")
	flag.StringVar(paramsHttpMethod /*        */, "method" /*                */, "GET" /*  */, "[optional] HTTP method")
	flag.StringVar(paramsBody /*              */, "body" /*                  */, "" /*     */, "[optional] Request body")
	flag.StringVar(paramsHostHeader /*        */, "host-header" /*           */, "" /*     */, "[optional] Host header")
	flag.StringVar(paramsUuidHeaderName /*    */, "uuid-header-name" /*      */, "" /*     */, "[optional] Header name for Uuid")
	flag.IntVar(paramsLoopCount /*            */, "loop-count" /*            */, 3 /*      */, "[optional] Loop count")
	flag.IntVar(paramsWaitMillSecond /*       */, "wait-millisecond" /*      */, 1000 /*   */, "[optional] Wait millisecond")
	flag.BoolVar(paramsPrettyHttpMessage /*   */, "pretty-http-message" /*   */, false /*  */, "[optional] Print pretty http message")
	flag.BoolVar(paramsNoOutputResponse /*    */, "no-response-output" /*    */, false /*  */, "[optional] Don't output response")
	flag.BoolVar(paramsSkipTlsVerification /* */, "skip-tls-verification" /* */, false /*  */, "[optional] Skip tls verification")
	flag.BoolVar(paramsHelp /*                */, "help" /*                  */, false /*  */, "help")
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
	tlsConfig := &tls.Config{
		InsecureSkipVerify: *paramsSkipTlsVerification,
	}
	sslKeyLogFile := os.Getenv("SSLKEYLOGFILE")
	if sslKeyLogFile != "" {
		w, err := os.OpenFile(sslKeyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		handleError(err, "SSLKEYLOGFILE os.OpenFile")
		defer func() { handleError(w.Close(), "SSLKEYLOGFILE file w.Close()") }()
		tlsConfig.KeyLogWriter = w
	}

	client := http.Client{
		Transport: CreateCustomTransport(tlsConfig),
	}

	fmt.Println("#--------------------")
	fmt.Println("# Command information")
	fmt.Println("#--------------------")
	fmt.Printf("Target URL            : %s\n", *paramsTargetUrl)
	fmt.Printf("HTTP Method           : %s\n", *paramsHttpMethod)
	fmt.Printf("Request body          : %s\n", *paramsBody)
	fmt.Printf("Host header           : %s\n", *paramsHostHeader)
	fmt.Printf("Loop count            : %d\n", *paramsLoopCount)
	fmt.Printf("Wait millsecond       : %d\n", *paramsWaitMillSecond)
	fmt.Printf("Uuid header name      : %s\n", *paramsUuidHeaderName)
	fmt.Printf("Skip Tls Verification : %t\n", *paramsSkipTlsVerification)
	fmt.Printf("No output response    : %t\n", *paramsNoOutputResponse)
	fmt.Printf("SSLKEYLOGFILE         : %s\n", sslKeyLogFile)

	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyPrettyHttpLog, *paramsPrettyHttpMessage)
	ctx = context.WithValue(ctx, ContextKeyNoOutputResponse, *paramsNoOutputResponse)

	headers := httpHeaderEmptyMap
	if *paramsUuidHeaderName != "" {
		headers[*paramsUuidHeaderName] = createUuid()
	}

	for i := 0; i < *paramsLoopCount; i++ {
		_, _ = DoHttpRequest(ctx, client, *paramsHttpMethod, *paramsTargetUrl, headers, *paramsBody)
		time.Sleep(time.Duration(*paramsWaitMillSecond) * time.Millisecond)
	}
}

// =======================================
// HTTP Utils
// =======================================

// Debugging HTTP Client requests with Go · Jamie Tanna | Software Engineer
// https://www.jvt.me/posts/2023/03/11/go-debug-http/
type CustomTransport struct {
	// Embed default transport
	*http.Transport
}

func (s *CustomTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	httpMessageBytes, err := httputil.DumpRequestOut(r, true)
	handleError(err, "httputil.DumpRequestOut(r, true)")

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

	fmt.Printf("Req. %s%s", time.Now().Format(TimeFormat), adjustMessage("\n"+string(httpMessageBytes)+"\n"))
	resp, err := s.Transport.RoundTrip(r)
	handleError(err, "s.Transport.RoundTrip(r)")
	respBytes := make([]byte, 0)
	if !r.Context().Value(ContextKeyNoOutputResponse).(bool) {
		respBytes, err = httputil.DumpResponse(resp, true)
	}
	handleError(err, "httputil.DumpResponse(resp, true)")
	fmt.Printf("Res. %s%s\n", time.Now().Format(TimeFormat), adjustMessage("\n"+string(respBytes)))

	return resp, err
}

func CreateCustomTransport(tlsConfig *tls.Config) *CustomTransport {
	customTr := &CustomTransport{Transport: http.DefaultTransport.(*http.Transport).Clone()}
	if tlsConfig != nil {
		customTr.TLSClientConfig = tlsConfig
	}
	return customTr
}

func DoHttpRequest(ctx context.Context, client http.Client, method string, url string, headers map[string]string, body string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	handleError(err, "http.NewRequestWithContext")
	return client.Do(req)
}

// =======================================
// Json Utils
// =======================================

// ToJsonObject json bytes to interface{} object
func ToJsonObject(body []byte) interface{} {
	var jsonObject interface{}
	err := json.Unmarshal(body, &jsonObject)
	handleError(err, "json.Unmarshal")
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
	return hex.EncodeToString(shaBytes[:16])
}

func handleError(err error, prefixErrMessage string) {
	if err != nil {
		fmt.Printf("%s [ERROR %s]: %v\n", time.Now().Format(TimeFormat), prefixErrMessage, err)
	}
}
