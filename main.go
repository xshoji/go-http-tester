package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	UsageRequiredPrefix          = "\u001B[33m(REQ)\u001B[0m "
	UsageDummy                   = "########"
	HttpContentTypeHeader        = "Content-Type"
	ContextKeyPrettyHttpLog      = "ContextKeyLoggingPrettyHttpLog"
	ContextKeyNoReadResponseBody = "ContextKeyNoReadResponseBody"
	TimeFormat                   = "2006-01-02 15:04:05.9999 [MST]"
)

var (
	// Command options ( the -h, --help option is defined by default in the flag package )
	commandDescription        = "HTTP request/response testing tool."
	commandOptionMaxLength    = "28"
	optionTargetUrl           = defineFlagValue("t", "target-host" /*            */, UsageRequiredPrefix+"Target url (sample https://**.**/** )" /* */, "").(*string)
	optionHttpMethod          = defineFlagValue("m", "method" /*                 */, "HTTP method" /*                                               */, "GET").(*string)
	optionBody                = defineFlagValue("b", "body" /*                   */, "Request body" /*                                              */, "").(*string)
	optionHostHeader          = defineFlagValue("ho", "host-header" /*           */, "Host header" /*                                               */, "").(*string)
	optionUuidHeaderName      = defineFlagValue("u", "uuid-header-name" /*       */, "Header name for uuid in the request" /*                       */, "").(*string)
	optionNetworkType         = defineFlagValue("n", "network-type" /*           */, "Network type [ values: \"tcp4\", \"tcp6\" ]" /*               */, "tcp4").(*string)
	optionLoopCount           = defineFlagValue("l", "loop-count" /*             */, "Loop count" /*                                                */, 3).(*int)
	optionWaitMillSecond      = defineFlagValue("w", "wait-millisecond" /*       */, "Wait millisecond" /*                                          */, 1000).(*int)
	optionPrettyHttpMessage   = defineFlagValue("p", "pretty-http-message" /*    */, "Print pretty http message" /*                                 */, false).(*bool)
	optionNoReadResponseBody  = defineFlagValue("no", "no-read-response-body" /* */, "Don't read response body (If this is enabled, http connection will be not reused between each request)", false).(*bool)
	optionSkipTlsVerification = defineFlagValue("s", "skip-tls-verification" /*  */, "Skip tls verification" /*                                     */, false).(*bool)
	optionDisableHttp2        = defineFlagValue("d", "disable-http2" /*          */, "Disable HTTP/2" /*                                            */, false).(*bool)

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
	flag.Usage = customUsage(os.Stdout, os.Args[0], commandDescription, commandOptionMaxLength)
}

// Build:
// $ GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o /tmp/go-http-tester main.go
// $ go build -ldflags="-s -w" -trimpath -o "/tmp/$(basename "${PWD}")" main.go
func main() {
	flag.Parse()
	if *optionTargetUrl == "" {
		fmt.Printf("\n[ERROR] Missing required option\n\n")
		flag.Usage()
		os.Exit(1)
	}

	sslKeyLogFile := os.Getenv("SSLKEYLOGFILE")
	client := http.Client{
		Transport: CreateCustomTransport(
			CreateTlsConfig(*optionSkipTlsVerification, sslKeyLogFile),
			*optionDisableHttp2,
			*optionNetworkType,
		),
	}

	fmt.Printf("[ Environment variable ]\nSSLKEYLOGFILE: %s\n\n", sslKeyLogFile)
	fmt.Printf("[ Command options ]\n")
	flag.VisitAll(func(a *flag.Flag) {
		if a.Usage == UsageDummy {
			return
		}
		fmt.Printf("  -%-"+commandOptionMaxLength+"s %s\n",
			fmt.Sprintf("%-2s, -%s %v", strings.Split(a.Usage, UsageDummy)[0], a.Name, a.Value),
			strings.Trim(strings.Split(a.Usage, UsageDummy)[1], "\n"))
	})
	fmt.Printf("\n\n")

	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyPrettyHttpLog, *optionPrettyHttpMessage)
	ctx = context.WithValue(ctx, ContextKeyNoReadResponseBody, *optionNoReadResponseBody)

	headers := createHttpHeaderEmpty()
	if *optionUuidHeaderName != "" {
		headers[*optionUuidHeaderName] = createUuid()
	}

	for i := 0; i < *optionLoopCount; i++ {
		_, _ = DoHttpRequest(ctx, client, *optionHttpMethod, *optionTargetUrl, headers, *optionHostHeader, strings.NewReader(*optionBody))
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

func DoHttpRequest(ctx context.Context, client http.Client, method string, url string, headers map[string]string, hostHeader string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if hostHeader != "" {
		req.Host = hostHeader
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
func defineFlagValue[T comparable](short, long, description string, defaultValue T) any {
	flagUsage := short + UsageDummy + description
	var zero T
	if defaultValue != zero {
		flagUsage = flagUsage + fmt.Sprintf(" (default %v)", defaultValue)
	}

	switch v := any(defaultValue).(type) {
	case string:
		f := flag.String(short, v, UsageDummy)
		flag.StringVar(f, long, v, flagUsage)
		return f
	case int:
		f := flag.Int(short, v, UsageDummy)
		flag.IntVar(f, long, v, flagUsage)
		return f
	case bool:
		f := flag.Bool(short, v, UsageDummy)
		flag.BoolVar(f, long, v, flagUsage)
		return f
	default:
		panic("unsupported flag type")
	}
}

func customUsage(output io.Writer, cmdName, description, fieldWidth string) func() {
	return func() {
		fmt.Fprintf(output, "Usage: %s [OPTIONS] [-h, --help]\n\n", cmdName)
		fmt.Fprintf(output, "Description:\n  %s\n\n", description)
		fmt.Fprintln(output, "Options:")

		optionUsages := make([]string, 0)
		flag.VisitAll(func(f *flag.Flag) {
			if f.Usage == UsageDummy {
				return
			}
			valueType := strings.Replace(strings.Replace(fmt.Sprintf("%T", f.Value), "*flag.", "", -1), "Value", "", -1)
			format := "  -%-2s, --%-" + fieldWidth + "s %s\n"
			short := strings.Split(f.Usage, UsageDummy)[0]
			mainUsage := strings.Split(f.Usage, UsageDummy)[1]
			optionUsages = append(optionUsages, fmt.Sprintf(format, short, f.Name+" "+valueType, mainUsage))
		})
		sort.SliceStable(optionUsages, func(i, j int) bool {
			return strings.Count(optionUsages[i], UsageRequiredPrefix) > strings.Count(optionUsages[j], UsageRequiredPrefix)
		})
		fmt.Fprint(output, strings.Join(optionUsages, ""))
	}
}
