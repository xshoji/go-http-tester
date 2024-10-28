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
	UsageRequiredPrefix          = "\u001B[33m[required]\u001B[0m "
	UsageDummy                   = "########"
	CommandDescription           = "HTTP request/response testing tool."
	HttpContentTypeHeader        = "Content-Type"
	ContextKeyPrettyHttpLog      = "ContextKeyLoggingPrettyHttpLog"
	ContextKeyNoReadResponseBody = "ContextKeyNoReadResponseBody"
	TimeFormat                   = "2006-01-02 15:04:05.9999 [MST]"
)

var (
	// Required parameters
	paramsTargetUrl = defineStringParam("t", "target-host", UsageRequiredPrefix+"target url (sample https://****.***/***/*** )", "")

	// Optional parameters
	paramsHttpMethod          = defineStringParam("m", "method", "HTTP method", "GET")
	paramsBody                = defineStringParam("b", "body", "request body", "")
	paramsHostHeader          = defineStringParam("ho", "host-header", "host header", "")
	paramsUuidHeaderName      = defineStringParam("u", "uuid-header-name", "header name for uuid in the request", "")
	paramsNetworkType         = defineStringParam("n", "network-type", "network type [ values: \"tcp4\", \"tcp6\" ]", "tcp4")
	paramsLoopCount           = defineIntParam("l", "loop-count", "loop count", 3)
	paramsWaitMillSecond      = defineIntParam("w", "wait-millisecond", "wait millisecond", 1000)
	paramsPrettyHttpMessage   = defineBoolParam("p", "pretty-http-message", "print pretty http message")
	paramsNoReadResponseBody  = defineBoolParam("no", "no-read-response-body", "don't read response body (If this is enabled, http connection will be not reused between each request)")
	paramsSkipTlsVerification = defineBoolParam("s", "skip-tls-verification", "skip tls verification")
	paramsDisableHttp2        = defineBoolParam("d", "disable-http2", "disable HTTP/2")
	paramsHelp                = defineBoolParam("h", "help", "show help")

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
	adjustUsage()
}

func main() {

	flag.Parse()
	if *paramsHelp || *paramsTargetUrl == "" {
		flag.Usage()
		os.Exit(0)
	}

	sslKeyLogFile := os.Getenv("SSLKEYLOGFILE")
	client := http.Client{
		Transport: CreateCustomTransport(
			CreateTlsConfig(*paramsSkipTlsVerification, sslKeyLogFile),
			*paramsDisableHttp2,
			*paramsNetworkType,
		),
	}

	fmt.Println("#--------------------")
	fmt.Println("# Command information")
	fmt.Println("#--------------------")
	fmt.Printf("target url            : %s\n", *paramsTargetUrl)
	fmt.Printf("HTTP method           : %s\n", *paramsHttpMethod)
	fmt.Printf("request body          : %s\n", *paramsBody)
	fmt.Printf("host header           : %s\n", *paramsHostHeader)
	fmt.Printf("loop count            : %d\n", *paramsLoopCount)
	fmt.Printf("wait millsecond       : %d\n", *paramsWaitMillSecond)
	fmt.Printf("uuid header name      : %s\n", *paramsUuidHeaderName)
	fmt.Printf("skip tls Verification : %t\n", *paramsSkipTlsVerification)
	fmt.Printf("network type          : %s\n", *paramsNetworkType)
	fmt.Printf("no read response body : %t\n", *paramsNoReadResponseBody)
	fmt.Printf("disable HTTP/2        : %t\n", *paramsDisableHttp2)
	fmt.Printf("SSLKEYLOGFILE         : %s\n", sslKeyLogFile)

	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyPrettyHttpLog, *paramsPrettyHttpMessage)
	ctx = context.WithValue(ctx, ContextKeyNoReadResponseBody, *paramsNoReadResponseBody)

	headers := createHttpHeaderEmpty()
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

func defineStringParam(short, long, description, defaultValue string) (v *string) {
	// Define short parameters ( this default value and usage will be not used ).
	v = flag.String(short, "", UsageDummy)
	// Define long parameters and description ( set default value here if you need ).
	flag.StringVar(v, long, defaultValue, description)
	return
}

func defineIntParam(short, long, description string, defaultValue int) (v *int) {
	v = flag.Int(short, 0, UsageDummy)
	flag.IntVar(v, long, defaultValue, description)
	return
}

func defineBoolParam(short, long, description string) (v *bool) {
	v = flag.Bool(short, false, UsageDummy)
	flag.BoolVar(v, long, false, description)
	return
}

func adjustUsage() {
	// Get default flags usage
	b := new(bytes.Buffer)
	func() { flag.CommandLine.SetOutput(b); flag.Usage(); flag.CommandLine.SetOutput(os.Stderr) }()
	// Get default flags usage
	re := regexp.MustCompile("(-\\S+)( *\\S*)+\n*\\s+" + UsageDummy + "\n*\\s+(-\\S+)( *\\S*)+\n\\s+(.+)")
	usageParams := re.FindAllString(b.String(), -1)
	maxLengthParam := 0.0
	sort.Slice(usageParams, func(i, j int) bool {
		maxLengthParam = math.Max(maxLengthParam, math.Max(float64(len(re.ReplaceAllString(usageParams[i], "$1, -$3$4"))), float64(len(re.ReplaceAllString(usageParams[j], "$1, -$3$4")))))
		if len(strings.Split(usageParams[i]+usageParams[j], UsageRequiredPrefix))%2 == 1 {
			return strings.Compare(usageParams[i], usageParams[j]) == -1
		} else {
			return strings.Index(usageParams[i], UsageRequiredPrefix) >= 0
		}
	})
	usage := strings.Replace(strings.Replace(strings.Split(b.String(), "\n")[0], ":", " [OPTIONS]", -1), " of ", ": ", -1) + "\n\nDescription:\n  " + CommandDescription + "\n\nOptions:\n"
	for _, v := range usageParams {
		usage += fmt.Sprintf("%-6s%-"+strconv.Itoa(int(maxLengthParam))+"s", re.ReplaceAllString(v, "  $1,"), re.ReplaceAllString(v, "-$3$4")) + re.ReplaceAllString(v, "$5\n")
	}
	flag.Usage = func() { _, _ = fmt.Fprintf(flag.CommandLine.Output(), usage) }
}
