# go-http-tester

Http testing tool implemented by golang.

# Usage

```
$ ./go-http-tester
Usage: ./go-http-tester [OPTIONS]

Description:
  HTTP request/response testing tool.

Options:
  -t, --target-host string         (REQ) Target url (sample https://**.**/** )
  -b, --body string                Request body
  -d, --disable-http2              Disable HTTP/2
  -ho,--host-header string         Host header
  -l, --loop-count int             Loop count (default 3)
  -m, --method string              HTTP method (default "GET")
  -n, --network-type string        Network type [ values: "tcp4", "tcp6" ] (default "tcp4")
  -no,--no-read-response-body      Don't read response body (If this is enabled, http connection will be not reused between each request)
  -p, --pretty-http-message        Print pretty http message
  -s, --skip-tls-verification      Skip tls verification
  -u, --uuid-header-name string    Header name for uuid in the request
  -w, --wait-millisecond int       Wait millisecond (default 1000)
```
