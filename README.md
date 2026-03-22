\# Rust Reverse Proxy



A secure, production-grade reverse proxy built with Rust using \*\*Tokio\*\* and \*\*Hyper\*\*.  

Built as part of a Secure Coding course to demonstrate async networking, load balancing, and security best practices.



\---



\## Features



| Feature | Details |

|---|---|

| Reverse Proxy | Accepts HTTPS on port 8443, forwards to HTTP backends |

| Round Robin Load Balancing | Distributes requests evenly across 3 backends |

| Automatic Failover | Skips unhealthy backends, retries next available |

| Auto Recovery | Probes dead backends every 5s and restores them |

| Rate Limiting | Fixed window — 5 requests per 10s per IP, returns 429 |

| Security Headers | `X-Content-Type-Options` and `Strict-Transport-Security` |

| HTTPS / TLS | Self-signed certificate via `rustls` (no OpenSSL) |

| Structured Logging | JSON logs to file + colored console output |

| Async / Concurrent | Every connection runs in its own Tokio task |



\---



\## Project Structure



```

reverse-proxy/

├── src/

│   └── main.rs        # All proxy logic in a single file

├── Cargo.toml         # Dependencies

├── Cargo.lock         # Pinned dependency versions

├── .gitignore         # Excludes target/ and logs/

└── README.md

```



\---



\## Dependencies



| Crate | Version | Purpose |

|---|---|---|

| `hyper` | 0.14 | Async HTTP client and server |

| `tokio` | 1 | Async runtime |

| `tokio-rustls` | 0.24 | TLS over Tokio streams |

| `rustls` | 0.21 | Pure-Rust TLS (no OpenSSL) |

| `rustls-pemfile` | 1 | Parse PEM certificates |

| `rcgen` | 0.11 | Generate self-signed certificates |

| `tracing` | 0.1 | Structured logging macros |

| `tracing-subscriber` | 0.3 | Log output (console + file) |

| `tracing-appender` | 0.2 | Rolling file writer |

| `chrono` | 0.4 | Timestamps |



\---



\## Prerequisites



\- Rust (install via https://rustup.rs)

\- Python 3 (for running test backend servers)



\---



\## How to Run



\*\*1. Clone the repository\*\*

```bash

git clone https://github.com/Kavin-010/Reverse-proxy.git

cd Reverse-proxy

```



\*\*2. Start backend servers (open 3 separate terminals)\*\*

```bash

python -m http.server 3000 --bind 127.0.0.1

python -m http.server 3001 --bind 127.0.0.1

python -m http.server 3002 --bind 127.0.0.1

```



\*\*3. Start the proxy\*\*

```bash

cargo run

```



The proxy will start at `https://localhost:8443`



```

=========================================

&#x20; Hyper Reverse Proxy - HTTPS/TLS

=========================================

&#x20; Listening  : https://0.0.0.0:8443

&#x20; TLS        : Self-signed cert (rustls)

&#x20; Strategy   : Round Robin + Failover

&#x20; Rate Limit : 5 req per 10s per IP

&#x20; Sec Headers: X-Content-Type-Options

&#x20;              Strict-Transport-Security

\-----------------------------------------

&#x20; Backend 1 : http://localhost:3000

&#x20; Backend 2 : http://localhost:3001

&#x20; Backend 3 : http://localhost:3002

=========================================

```



\---



\## Testing



\### Basic Request

```bash

curl -k https://localhost:8443/

```

Expected: `200 OK`



\---



\### Round Robin Load Balancing

```bash

curl -k https://localhost:8443/

curl -k https://localhost:8443/

curl -k https://localhost:8443/

```

Expected in proxy logs:

```

Routing request backend=http://localhost:3000

Routing request backend=http://localhost:3001

Routing request backend=http://localhost:3002

```



\---



\### Rate Limiting

```powershell

for ($i=1; $i -le 10; $i++) {

&#x20;   $code = curl.exe -k -s -o NUL -w "%{http\_code}" --no-keepalive https://localhost:8443/

&#x20;   Write-Host "Request $i : $code"

}

```

Expected:

```

Request 1-5  : 200   (within limit)

Request 6-10 : 429   (rate limit exceeded)

```

Wait 10 seconds — the window resets and requests return 200 again.



\---



\### Failover

```bash

\# Stop one backend (Ctrl+C on port 3000 terminal)

\# Then send requests

curl -k https://localhost:8443/

curl -k https://localhost:8443/

```

Expected: Proxy automatically skips the dead backend and routes to healthy ones.



\---



\### Security Headers

```bash

curl -k -v https://localhost:8443/ 2>\&1 | grep -i "content-type-options\\|strict-transport"

```

Expected:

```

x-content-type-options: nosniff

strict-transport-security: max-age=31536000; includeSubDomains

```



\---



\### Log File

```bash

cat logs/proxy.log.YYYY-MM-DD

```

Expected JSON output:

```json

{"timestamp":"2026-03-22T17:47:43Z","level":"INFO","fields":{"message":"Incoming request","method":"GET","path":"/","client\_ip":"127.0.0.1"}}

{"timestamp":"2026-03-22T17:47:43Z","level":"INFO","fields":{"message":"Routing request","backend":"http://localhost:3000"}}

{"timestamp":"2026-03-22T17:47:44Z","level":"INFO","fields":{"message":"Request completed","status":"200 OK","latency":"311ms"}}

{"timestamp":"2026-03-22T17:47:50Z","level":"WARN","fields":{"message":"Rate limit exceeded","client\_ip":"127.0.0.1","limit":5,"window":10}}

```



\---



\## Security Design Decisions



\### HTTPS with rustls

All client-to-proxy traffic is encrypted using TLS 1.3. `rustls` was chosen over OpenSSL because it is written in pure Rust — memory-safe by design with no risk of buffer overflows or use-after-free vulnerabilities that have historically affected OpenSSL.



\### X-Content-Type-Options: nosniff

Prevents browsers from MIME-sniffing responses. Without this header, a browser might execute a `.txt` file as JavaScript if it resembles code — a known XSS attack vector. The `nosniff` directive forces the browser to trust the declared `Content-Type` exactly.



\### Strict-Transport-Security (HSTS)

```

Strict-Transport-Security: max-age=31536000; includeSubDomains

```

Once a browser receives this header, it refuses to connect over plain HTTP for 1 year. This prevents protocol downgrade attacks where an attacker intercepts an HTTP redirect to HTTPS.



\### Rate Limiting — Fixed Window Algorithm

Each IP address gets a fixed quota of 5 requests per 10-second window. The counter resets after the window expires. This protects against:

\- Brute force attacks on login endpoints

\- Denial of Service by request flooding

\- Credential stuffing attacks



The `X-Forwarded-For` header is read to correctly identify the real client IP even behind upstream proxies.



\### Atomic Operations for Concurrency

The round-robin counter uses `AtomicUsize` and backend health flags use `AtomicBool`. These are lock-free operations that are safe across concurrent Tokio tasks without needing a Mutex, eliminating the risk of deadlocks in the hot path.



\---



\## HTTP Status Codes



| Code | Meaning | When returned |

|---|---|---|

| `200` | OK | Request forwarded successfully |

| `429` | Too Many Requests | Rate limit exceeded |

| `502` | Bad Gateway | Backend connection failed |

| `503` | Service Unavailable | All backends are down |

| `504` | Gateway Timeout | Backend did not respond in time |



\---



\## Architecture



```

Client (HTTPS)

&#x20;    |

&#x20;    | TLS encrypted

&#x20;    v

\[Port 8443 - Reverse Proxy]

&#x20;    |

&#x20;    |-- Rate Limit Check (per IP)

&#x20;    |-- Pick healthy backend (Round Robin)

&#x20;    |-- Rewrite URI + headers

&#x20;    |-- Forward request (HTTP)

&#x20;    |

&#x20;    +---> Backend 3000

&#x20;    +---> Backend 3001

&#x20;    +---> Backend 3002

&#x20;    |

&#x20;    |-- Add security headers to response

&#x20;    |-- Log request + response

&#x20;    |

&#x20;    v

Client receives response

```

