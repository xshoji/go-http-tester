# go-http-tester

Http testing tool implemented by golang.

# Usage

```
$ ./go-http-tester
Usage of ./go-http-tester:
  -t, --target-host string        [Required] Target URL (sample https://****.***/***/*** )
  -m, --method string             HTTP method (default "GET")
  -d2, --disable-http2            Disable HTTP/2
  -h, --help                      Show help
  -hh, --host-header string       Host header
  -l, --loop-count int            Loop count (default 3)
  -a6, --allow-ipv6               Allow IPv6 (default: IPv4 only)
  -n, --no-read-response-body     Don't read response body (If this is enabled, http connection will be not reused between each request)
  -p, --pretty-http-message       Print pretty http message
  -s, --skip-tls-verification     Skip tls verification
  -b, --body string               Request body
  -uh, --uuid-header-name string  Header name for uuid in the request
  -w, --wait-millisecond int      Wait millisecond (default 1000)
```
