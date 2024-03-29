# go-http-tester

Http testing tool implemented by golang.

# Usage

```
$ ./go-http-tester
Usage of ./go-http-tester:
  -t, --target-host string        [Required] Target URL (sample https://****.***/***/*** )
  -b, --body string               Request body
  -d2, --disable-http2            Disable HTTP/2
  -h, --help                      Show help
  -hh, --host-header string       Host header
  -l, --loop-count int            Loop count (default 3)
  -m, --method string             HTTP method (default "GET")
  -ne, --network-type string      Network type [ values: "tcp4", "ipv6" ] (default "tcp4")
  -no, --no-read-response-body    Don't read response body (If this is enabled, http connection will be not reused between each request)
  -p, --pretty-http-message       Print pretty http message
  -s, --skip-tls-verification     Skip tls verification
  -uh, --uuid-header-name string  Header name for uuid in the request
  -w, --wait-millisecond int      Wait millisecond (default 1000)
```
