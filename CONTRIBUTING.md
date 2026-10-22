# Contributing

Build with Go 1.26+ on macOS/Linux and run `make check` and `make smoke`. Keep tests offline with fake transports and non-functional synthetic material. Never commit account data or provider responses containing values.

Keep remote writes out of this alpha. Provider adapters must return partial coverage after failures; inaccessible values cannot become exact matches. Raw material stays inside `internal/scan`; report and case types contain metadata only. Authentication must be independent of suspected credentials.

Add a regression test for leaks, false completion, scope widening or dropped evidence. Report test limitations honestly. Before introducing a new provider contract, link the official documentation and record permissions and a controlled smoke result. Do not equate fake tests with live validation.
