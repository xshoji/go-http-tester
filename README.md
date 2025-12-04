# go-http-tester

Http testing tool implemented by golang.

# Usage

```
$ ./go-http-tester
Usage: go-http-tester --target-host <string> [OPTIONS]

Description:
  HTTP request/response testing tool.

Options:
  -t, --target-host <string>            (required) Target URL (e.g. https://domain/path)
  -b, --body <string>                   Request body
  -d, --disable-http2                   Disable HTTP/2 support
  -H, --host-header <string>            Host header
  -i, --ignore-response-body            Don't read response body (If this is enabled, http connection will be not reused between each request)
  -l, --loop-count <int>                Loop count (default 3)
  -m, --method <string>                 HTTP method (default GET)
  -n, --network-type <string>           Network type { tcp4 | tcp6 } (default tcp4)
  -p, --pretty-http-message             Print pretty http message
  -s, --skip-tls-verification           Skip tls verification
  -u, --uuid-header-name <string>       Header name for uuid in the request
  -w, --wait-millisecond <int>          Wait millisecond (default 1000)
```
