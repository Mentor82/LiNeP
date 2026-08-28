# V0.2 tests

Test work for Issue #10 lives here.

Initial suites:

- envelope encode/decode and validation
- identity scope separation
- semantic `event_seq` validation
- fragmentation/reassembly independence
- targeted cancellation
- exactly-one terminal outcome
- bounded backpressure
- embedding-space compatibility
- persistent-session multiplexing and stream isolation

The existing V0.1 test suite remains authoritative for regression protection and should not be rewritten to accommodate V0.2.
