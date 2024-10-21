# go-http-tester

Http testing tool implemented by golang.

# Usage

```
$ ./go-http-tester
Usage of /tmp/go-http-tester:

Description:
  HTTP request/response testing tool.

Options:
  -t, --target-host string        [required] target url (sample https://****.***/***/*** )
  -b, --body string               request body
  -d, --disable-http2             disable HTTP/2
  -h, --help                      show help
  -ho, --host-header string       host header
  -l, --loop-count int            loop count (default 3)
  -m, --method string             HTTP method (default "GET")
  -n, --network-type string       network type [ values: "tcp4", "tcp6" ] (default "tcp4")
  -no, --no-read-response-body    don't read response body (If this is enabled, http connection will be not reused between each request)
  -p, --pretty-http-message       print pretty http message
  -s, --skip-tls-verification     skip tls verification
  -u, --uuid-header-name string   header name for uuid in the request
  -w, --wait-millisecond int      wait millisecond (default 1000)
```
