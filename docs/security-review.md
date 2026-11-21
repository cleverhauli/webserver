# Security review

Reviewed: 2026-11-21, at the end of Step 11a.
Scope: every network-facing code path in this repository.
Method: list the ways a stranger could abuse the server, find the code that
stops each one, and confirm an automated test proves it. Gaps are recorded as
findings and fixed or listed under residual risks.

## What is covered

| Threat | Defense | Where | Proven by |
|---|---|---|---|
| Request smuggling | One framing rule. Reject Content-Length with Transfer-Encoding, conflicting or invalid lengths, duplicate Transfer-Encoding, and chunked on HTTP/1.0. The proxy re-frames requests itself and checks upstream responses just as strictly. | http/parser.rs, proxy.rs | conflicting_content_lengths_get_400, content_length_together_with_transfer_encoding_gets_400, misbehaving_upstreams_get_502 |
| Slow request (slowloris) | One total deadline for the headers and another for the body, however slowly bytes arrive. | connection.rs, net_util.rs | trickling_bytes_cannot_hold_a_connection_open |
| Slow reader | Every write has a time limit. | net_util.rs | writes_to_a_client_that_never_reads_time_out |
| Connection hoarding | Idle timeout, request cap per connection, global limit, per-address limit. | server.rs, ip_limit.rs | idle_keep_alive_connections_are_closed, max_requests_per_connection_is_enforced, the_connection_limit_gives_503_and_then_recovers, one_address_cannot_hold_every_connection |
| Oversized input | Header, target and body limits, checked before the data is read. | parser.rs, chunked.rs | oversized_bodies_get_413_before_they_are_sent, oversized_headers_get_431, very_long_targets_get_414 |
| Path traversal | Decode first, then refuse dot segments, backslashes, colons, control characters, dotfiles and Windows device names. Then resolve the real path and check it is inside the root. | static_files.rs | path_traversal_attempts_never_leak_files and the paths_* property tests |
| Header injection | Header names and values with line breaks or control characters are dropped. | http/response.rs, config.rs | header_injection_is_impossible |
| Open redirect, Host abuse | The redirect target is rebuilt from a strictly validated host. | redirect.rs | the_redirect_refuses_suspicious_host_headers |
| Open proxy (SSRF) | Upstreams come only from the config file. Absolute-form requests and CONNECT are never forwarded. Dot segments are refused. | proxy.rs | the_proxy_cannot_be_used_as_an_open_relay, paths_cannot_climb_out_of_the_route |
| Spoofed client identity | X-Forwarded-* headers are rebuilt, never copied. The status page refuses proxied requests. | proxy.rs, status.rs | forwarding_headers_are_ours_and_spoofed_ones_are_discarded, a_proxy_cannot_be_used_to_reach_an_upstreams_status_page |
| Weak TLS | rustls only. TLS 1.2 and 1.3. Safe defaults. Certificate and key checked at startup. Handshake timeout. No custom cryptography. | tls.rs | a_client_that_does_not_trust_the_certificate_is_refused, silent_connections_to_the_https_port_are_dropped |
| Information leaks | Generic error pages. Vague proxy errors. Query strings not logged. Log text sanitised. Status page off by default. | proxy.rs, logging.rs, status.rs | errors_become_vague_responses, a_forged_log_line_cannot_survive |
| Memory exhaustion | Files are streamed. Buffers are bounded. On-the-fly compression and proxied responses have size limits. | static_files.rs, proxy.rs | big_files_are_streamed_not_loaded, oversized_upstream_answers_get_502 |
| Crashes | Parser, decoder, paths and router are tested with random and mutated input. The compiler forbids unwrap, expect and panic in non-test code. CI fuzzes for a minute on every push. | lib.rs, tests/properties.rs | parser_survives_random_bytes and the CI fuzz job |
| Vulnerable dependencies | cargo audit runs in CI. Cargo.lock is committed. | .github/workflows/ci.yml | CI audit job |
| Secrets in git | Certificates and keys are ignored. The shipped config must have HTTPS, HSTS, the status page, query logging and the proxy example switched off. | .gitignore, tests/shipped_config.rs | the_shipped_config_works_on_a_fresh_checkout |
| Compression attacks | Only static files are compressed. Nothing is ever decompressed. Precompressed copies are served as they are. | compression.rs | images_are_never_compressed |

## Findings from this review

| # | Finding | Fix |
|---|---|---|
| F1 | No lingering close: an error answer could be destroyed by a TCP reset when the client kept sending. | The server keeps reading and discarding for up to 1 second (256 KiB at most) after saying goodbye. Test: a_rejection_reaches_a_client_that_keeps_sending. |
| F2 | One address could hold every connection slot. | max_connections_per_ip (default 100). Tests: ip_limit unit tests and one_address_cannot_hold_every_connection. |
| F3 | "Never panic on network input" was only a convention. | The compiler now denies unwrap, expect and panic in non-test code. |
| F4 | TCP_NODELAY was off, so small responses could be delayed. | Set on every accepted connection. |

## Residual risks (known and accepted for now)

- Worst-case memory is roughly max_connections x (max_header_bytes + max_body_bytes). For proxied requests it is the number of concurrent proxied requests x proxy_max_response_bytes. Size the limits to the machine's RAM.
- There is no per-request rate limiting, only connection limits.
- No HTTP/2. The proxy holds responses in memory, so there is no streaming or WebSocket support. It speaks plain HTTP to the upstream, does not rewrite Location headers, and passes paths to the upstream as they are (an upstream that decodes twice could still be surprised).
- Behind a load balancer or CDN, every visitor shares the balancer's address. The per-address limit and the status page allow-list then see only the balancer. Set max_connections_per_ip to 0 and keep the status page off.
- Certificate changes need a restart. There is no OCSP stapling. Protecting the private key file is the operator's job.
- A local attacker who can swap symlinks between the check and the open could escape the document root (a race that needs local access).
- The Server header reveals the software name and version.
- Static files only get X-Content-Type-Options. Content-Security-Policy and frame options depend on the site.
- No authentication features exist. The status page is address-based only.
- Logs are written to the terminal and are not rotated.

## Before exposing this server to the internet

- Run it as a non-root user. Open only ports 80 and 443 in the firewall.
- Use a real certificate. Make the key file readable only by the service user.
- Leave the status page off, or block /status at anything in front of the server.
- Turn HSTS on only after HTTPS works everywhere, and start with a small max-age.
- Size the limits to the RAM available.
- Run cargo audit before every release, and keep dependencies updated.
- Never commit certificates, keys or real secrets.
- Watch the refused and rejected counters on the status page, and the logs.