# go-http-tester

Http testing tool implemented by golang.

# Usage

```
$ ./go-http-tester
Usage: ./go-http-tester [OPTIONS]

Description:
  HTTP request/response testing tool.

Options:
  -t , --target-host string           (REQ) Target url (sample https://**.**/** )
  -b , --body string                  Request body
  -d , --disable-http2 bool           Disable HTTP/2
  -ho, --host-header string           Host header
  -l , --loop-count int               Loop count (default 3)
  -m , --method string                HTTP method (default GET)
  -n , --network-type string          Network type [ values: "tcp4", "tcp6" ] (default tcp4)
  -no, --no-read-response-body bool   Don't read response body (If this is enabled, http connection will be not reused between each request)
  -p , --pretty-http-message bool     Print pretty http message
  -s , --skip-tls-verification bool   Skip tls verification
  -u , --uuid-header-name string      Header name for uuid in the request
  -w , --wait-millisecond int         Wait millisecond (default 1000)
```

## Release

Release flow of this repository is integrated with github action.
Git tag pushing triggers release job.

```
# Release
git tag v0.0.2 && git push --tags

# Delete tag
echo "v0.0.1" |xargs -I{} bash -c "git tag -d {} && git push origin :{}"

# Delete tag and recreate new tag and push
echo "v0.0.2" |xargs -I{} bash -c "git tag -d {} && git push origin :{}; git tag {} -m \"Release beta version.\"; git push --tags"

```
