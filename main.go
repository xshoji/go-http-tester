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
	"maps"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	UsageRequiredPrefix          = "\u001B[33m[RQD]\u001B[0m "
	UsageDummy                   = "########"
	HttpContentTypeHeader        = "Content-Type"
	ContextKeyPrettyHttpLog      = "ContextKeyLoggingPrettyHttpLog"
	ContextKeyNoReadResponseBody = "ContextKeyNoReadResponseBody"
	TimeFormat                   = "2006-01-02 15:04:05.9999 [MST]"
)

var (
	commandDescription        = "HTTP request/response testing tool."
	optionTargetUrl           = defineFlagValue("t", "target-host", UsageRequiredPrefix+"Target url (sample https://****.***/***/*** )", "").(*string)
	optionHttpMethod          = defineFlagValue("m", "method", "HTTP method", "GET").(*string)
	optionBody                = defineFlagValue("b", "body", "Request body", "").(*string)
	optionHostHeader          = defineFlagValue("ho", "host-header", "Host header", "").(*string)
	optionUuidHeaderName      = defineFlagValue("u", "uuid-header-name", "Header name for uuid in the request", "").(*string)
	optionNetworkType         = defineFlagValue("n", "network-type", "Network type [ values: \"tcp4\", \"tcp6\" ]", "tcp4").(*string)
	optionLoopCount           = defineFlagValue("l", "loop-count", "Loop count", 3).(*int)
	optionWaitMillSecond      = defineFlagValue("w", "wait-millisecond", "Wait millisecond", 1000).(*int)
	optionPrettyHttpMessage   = defineFlagValue("p", "pretty-http-message", "Print pretty http message", false).(*bool)
	optionNoReadResponseBody  = defineFlagValue("no", "no-read-response-body", "Don't read response body (If this is enabled, http connection will be not reused between each request)", false).(*bool)
	optionSkipTlsVerification = defineFlagValue("s", "skip-tls-verification", "Skip tls verification", false).(*bool)
	optionDisableHttp2        = defineFlagValue("d", "disable-http2", "Disable HTTP/2", false).(*bool)
	optionHelp                = defineFlagValue("h", "help", "Show help", false).(*bool)

	// HTTP Header templates
	createHttpHeaderEmpty = func() map[string]string {
		return maps.Clone(make(map[string]string))
	}
	createHttpHeaderContentTypeForm = func() map[string]string {
		return maps.Clone(map[string]string{HttpContentTypeHeader: "application/x-www-form-urlencoded;charset=utf-8"})
	}
	createHttpHeaderContentTypeJson = func() map[string]string {
		return maps.Clone(map[string]string{HttpContentTypeHeader: "application/json"})
	}
)

func init() {
	formatUsage(commandDescription)
}

func main() {

	flag.Parse()
	if *optionHelp || *optionTargetUrl == "" {
		flag.Usage()
		os.Exit(0)
	}

	sslKeyLogFile := os.Getenv("SSLKEYLOGFILE")
	client := http.Client{
		Transport: CreateCustomTransport(
			CreateTlsConfig(*optionSkipTlsVerification, sslKeyLogFile),
			*optionDisableHttp2,
			*optionNetworkType,
		),
	}

	fmt.Println("#--------------------")
	fmt.Println("# Command information")
	fmt.Println("#--------------------")
	fmt.Printf("target url            : %s\n", *optionTargetUrl)
	fmt.Printf("HTTP method           : %s\n", *optionHttpMethod)
	fmt.Printf("request body          : %s\n", *optionBody)
	fmt.Printf("host header           : %s\n", *optionHostHeader)
	fmt.Printf("loop count            : %d\n", *optionLoopCount)
	fmt.Printf("wait millsecond       : %d\n", *optionWaitMillSecond)
	fmt.Printf("uuid header name      : %s\n", *optionUuidHeaderName)
	fmt.Printf("skip tls Verification : %t\n", *optionSkipTlsVerification)
	fmt.Printf("network type          : %s\n", *optionNetworkType)
	fmt.Printf("no read response body : %t\n", *optionNoReadResponseBody)
	fmt.Printf("disable HTTP/2        : %t\n", *optionDisableHttp2)
	fmt.Printf("SSLKEYLOGFILE         : %s\n", sslKeyLogFile)

	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyPrettyHttpLog, *optionPrettyHttpMessage)
	ctx = context.WithValue(ctx, ContextKeyNoReadResponseBody, *optionNoReadResponseBody)

	headers := createHttpHeaderEmpty()
	if *optionUuidHeaderName != "" {
		headers[*optionUuidHeaderName] = createUuid()
	}

	for i := 0; i < *optionLoopCount; i++ {
		_, _ = DoHttpRequest(ctx, client, *optionHttpMethod, *optionTargetUrl, headers, *optionBody)
		time.Sleep(time.Duration(*optionWaitMillSecond) * time.Millisecond)
	}
}

// =======================================
// HTTP Utils
// =======================================

// CustomTransport Debugging HTTP Client requests with Go: https://www.jvt.me/posts/2023/03/11/go-debug-http/
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
	// Goのnet/httpのkeep-aliveで気をつけること - Carpe Diem: https://christina04.hatenablog.com/entry/go-keep-alive
	respBytes, err := httputil.DumpResponse(resp, !r.Context().Value(ContextKeyNoReadResponseBody).(bool))
	handleError(err, "httputil.DumpResponse(resp, true)")
	fmt.Printf("Res. %s%s\n", time.Now().Format(TimeFormat), adjustMessage("\n"+string(respBytes)))

	return resp, err
}

// CreateCustomTransport
// [golang custom http client] #go #golang #http #client #timeouts #dns #resolver
// https://gist.github.com/Integralist/8a9cb8924f75ae42487fd877b03360e2?permalink_comment_id=4863513
func CreateCustomTransport(tlsConfig *tls.Config, disableHttp2 bool, networkType string) *CustomTransport {
	customTr := &CustomTransport{Transport: http.DefaultTransport.(*http.Transport).Clone()}
	if tlsConfig != nil {
		customTr.TLSClientConfig = tlsConfig
	}
	if disableHttp2 {
		// hdr-HTTP_2 - http package - net/http - Go Packages: https://pkg.go.dev/net/http#hdr-HTTP_2
		// disable HTTP/2 can do so by setting [Transport.TLSNextProto] (for clients) or [Server.TLSNextProto] (for servers) to a non-nil, empty map.
		customTr.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	}
	// Go http get force to use ipv4 - Stack Overflow : https://stackoverflow.com/questions/77718022/go-http-get-force-to-use-ipv4
	customTr.DialContext = func(ctx context.Context, network string, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, networkType, addr)
	}
	return customTr
}

func CreateTlsConfig(skipTlsVerification bool, sslKeyLogFile string) *tls.Config {
	// Set SSLKEYLOGFILE file path
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipTlsVerification,
	}
	if sslKeyLogFile != "" {
		w, err := os.OpenFile(sslKeyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		handleError(err, "SSLKEYLOGFILE os.OpenFile")
		defer func() { handleError(w.Close(), "SSLKEYLOGFILE file w.Close()") }()
		tlsConfig.KeyLogWriter = w
	}
	return tlsConfig
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
	var result interface{}
	var exists bool
	for _, key := range strings.Split(keyChain, ".") {
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

// Helper function for flag
func defineFlagValue(short, long, description string, defaultValue any) (f any) {
	switch defaultValue.(type) {
	case string:
		f = flag.String(short, "", UsageDummy)
		flag.StringVar(f.(*string), long, defaultValue.(string), description)
	case int:
		f = flag.Int(short, 0, UsageDummy)
		flag.IntVar(f.(*int), long, defaultValue.(int), description)
	case bool:
		f = flag.Bool(short, false, UsageDummy)
		flag.BoolVar(f.(*bool), long, defaultValue.(bool), description)
	default:
		panic("unsupported flag type")
	}
	return
}

func formatUsage(description string) {
	// Get default flags usage
	b := new(bytes.Buffer)
	func() { flag.CommandLine.SetOutput(b); flag.Usage(); flag.CommandLine.SetOutput(os.Stderr) }()
	// Get default flags usage
	re := regexp.MustCompile("(-\\S+)( *\\S*)+\n*\\s+" + UsageDummy + ".*\n*\\s+(-\\S+)( *\\S*)+\n\\s+(.+)")
	usageOptions := re.FindAllString(b.String(), -1)
	maxLength := 0.0
	sort.Slice(usageOptions, func(i, j int) bool {
		maxLength = math.Max(maxLength, math.Max(float64(len(re.ReplaceAllString(usageOptions[i], "$1, -$3$4"))), float64(len(re.ReplaceAllString(usageOptions[j], "$1, -$3$4")))))
		if len(strings.Split(usageOptions[i]+usageOptions[j], UsageRequiredPrefix))%2 == 1 {
			return strings.Compare(usageOptions[i], usageOptions[j]) == -1
		} else {
			return strings.Index(usageOptions[i], UsageRequiredPrefix) >= 0
		}
	})
	usage := strings.Replace(strings.Replace(strings.Split(b.String(), "\n")[0], ":", " [OPTIONS]", -1), " of ", ": ", -1) + "\n\nDescription:\n  " + description + "\n\nOptions:\n"
	for _, v := range usageOptions {
		usage += fmt.Sprintf("%-6s%-"+strconv.Itoa(int(maxLength))+"s", re.ReplaceAllString(v, "  $1,"), re.ReplaceAllString(v, "-$3$4")) + re.ReplaceAllString(v, "$5\n")
	}
	flag.Usage = func() { _, _ = fmt.Fprintf(flag.CommandLine.Output(), usage) }
}
