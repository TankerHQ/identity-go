<a href="#readme"><img src="https://tanker.io/images/github-logo.png" alt="Tanker logo" width="180" /></a>

# Identity SDK

[![Actions Status](https://github.com/TankerHQ/identity-go/workflows/Tests/badge.svg)](https://github.com/TankerHQ/identity-go/actions) [![codecov](https://codecov.io/gh/TankerHQ/identity-go/branch/master/graph/badge.svg)](https://codecov.io/gh/TankerHQ/identity-go) [![GoDoc][doc-badge]][doc]

Identity generation in GO for the [Tanker SDK](https://docs.tanker.io/latest/).

## Usage

Add the `github.com/TankerHQ/identity-go` import in your GO file and start using it.

See the [server-side code from the reference examples](https://pkg.go.dev/github.com/TankerHQ/identity-go#pkg-overview) that demonstrates a typical flow to safely deliver identities to your users.

Read more about identities in the [Tanker guide](https://docs.tanker.io/latest/guides/identity-management/).

## Development

Run tests:

```bash
go test -v
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/TankerHQ/identity-go.

[build-badge]: https://travis-ci.org/TankerHQ/identity-go.svg?branch=master
[build]: https://travis-ci.org/TankerHQ/identity-go
[doc-badge]: https://godoc.org/github.com/TankerHQ/identity-go?status.svg
[doc]: https://godoc.org/github.com/TankerHQ/identity-go
