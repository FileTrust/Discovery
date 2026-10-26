# Running a discovery node in production

The discovery process is a Python development HTTP server. It is fine as the
thing that *computes* the answer; it should not be the thing on the wire. A web
server terminates the outside connection and this listens on loopback behind it.

    internet ──► CDN (optional) ──► nginx / Caddy ──► 127.0.0.1:4601 (discovery)

## Go-live checklist

In this order. Step 4 must not happen before step 3.

1. [ ] `host` is `127.0.0.1` — the node is not reachable from outside.
2. [ ] `verify_signatures` and `verify_registry` are both `true`.
3. [ ] nginx or Caddy is running in front and sets `X-Forwarded-For`.
4. [ ] **Only now** set `trust_proxy_header: true`, plus `trusted_proxy_hops: 2`
       if a CDN is in front, and restart the node.
5. [ ] `curl https://<your-host>/health` answers, and `/v1/directory` returns
       the keeper and guardian counts you expect for the chain.

### Why step 4 comes last, and why it cannot be skipped

**Skip it, and one flooding user blocks every keeper.** With a proxy in front,
every request arrives from the proxy. The per-caller limit then counts the whole
network as one caller: the first flood empties the shared allowance and honest
keepers get `429`. The defence becomes the outage.

**Do it too early, and the limit stops working.** `X-Forwarded-For` is just a
header any client can send. On a node reachable directly, trusting it lets a
flood write a different address on every request and never reach its limit.

So the flag is only correct in one arrangement: a proxy in front, and no way to
reach the node around it. Both halves of that, or neither.

### How to tell which state you are in

```bash
curl -s -H 'X-Forwarded-For: 203.0.113.1' https://<your-host>/health
```

Then look at the node's log for that request. If it recorded `203.0.113.1`, the
header is being trusted — correct only if a proxy is genuinely in front. If it
recorded the proxy's address, the flag is off.

## Why not expose it directly

It has no TLS, no connection limit, no request-rate shaping, and one thread per
connection. The in-process protections added for this — a body size cap, a socket
timeout, a per-caller rate limit — cover the request once it arrives. They do not
cover the connection, and they are not a substitute for a server built for the
open internet.

## What the node does itself

| Protection | Where |
| --- | --- |
| Body size cap (1 MiB) | `read_json` → 413 |
| Drop a stalled connection (15 s) | `DiscoveryHandler.timeout` |
| Per-caller write limit | `rate_limited` → 429 + `Retry-After` |
| Network directory encoded once per version, with an ETag | `DirectoryStore.update` |
| Only changed rows for a caller holding a version | `DirectoryStore.answer` |
| Network directory as a plain file (+ `.gz`) | `<runtime>/public/<node>.directory.json` |

## Configuration

```json
{
  "nodes": [{ "id": "discovery-1", "host": "127.0.0.1", "port": 4601 }],
  "trust_proxy_header": true,
  "announce_rate_limit_per_minute": 30,
  "sync_rate_limit_per_minute": 240
}
```

`host` defaults to `127.0.0.1`. Binding anywhere else logs a warning at startup.

**`trust_proxy_header` matters more than it looks.** Behind a proxy every request
arrives from the proxy, so counting callers by socket address puts the whole
network in one bucket and one flood locks out every honest keeper. With this on,
the caller is taken from the rightmost `X-Forwarded-For` entry — the one the
proxy appended, so the address it actually saw.

Turn it on **only** when a trusted proxy is in front. Any client can send that
header, so trusting it on a directly exposed node lets a flood claim a new source
address on every request.

### Behind a CDN, count the hops

`trusted_proxy_hops` is how many trusted machines stand between the node and the
caller. Each one appends the address it saw, so the caller sits that many
entries from the right.

| Setup | `trusted_proxy_hops` |
| --- | --- |
| nginx or Caddy only | `1` (default) |
| Cloudflare → nginx → node | `2` |

Getting this wrong is not cosmetic. With a CDN and a count of `1`, the last
entry is the CDN's **own edge address**, so every request on the internet is
attributed to a handful of edges and the per-caller limit stops being per
caller — the same outage as having no header at all, reached by believing one.

Cloudflare also states the caller outright, which avoids counting anything:

```json
{ "trust_proxy_header": true, "client_ip_header": "CF-Connecting-IP" }
```

That header is only read when `trust_proxy_header` is on, for the same reason as
everything else here: off a trusted path it is just something the caller typed.

Either way, tell nginx to preserve the real caller:

```nginx
# Cloudflare's ranges, so $remote_addr is the caller and not the edge.
# https://www.cloudflare.com/ips/
set_real_ip_from 173.245.48.0/20;   # ... the rest of the published list
real_ip_header CF-Connecting-IP;
```

## nginx

```nginx
server {
    listen 443 ssl http2;
    server_name discovery.example.com;

    client_max_body_size 1m;
    client_body_timeout 10s;
    client_header_timeout 10s;

    limit_req_zone $binary_remote_addr zone=discovery:10m rate=10r/s;

    # The full network directory, served from disk (pre-compressed .gz beside
    # it). This is the hot path and it never reaches Python. A caller asking
    # for changes since a version (?since=...) goes to the node, which answers
    # with only the changed rows or 304.
    location = /v1/directory {
        if ($arg_since = "") {
            rewrite ^ /_directory_file last;
        }
        proxy_pass http://127.0.0.1:4601;
    }
    location = /_directory_file {
        internal;
        alias /path/to/runtime/public/discovery-1.directory.json;
        gzip_static on;
        default_type application/json;
        add_header Cache-Control "public, max-age=30";
    }

    location / {
        limit_req zone=discovery burst=20 nodelay;
        proxy_pass http://127.0.0.1:4601;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 15s;
    }
}
```

## Caddy

Shorter, and gets a certificate on its own.

```caddyfile
discovery.example.com {
    request_body { max_size 1MB }

    @full {
        path /v1/directory
        not query since=*
    }
    handle @full {
        root * /path/to/runtime/public
        rewrite * /discovery-1.directory.json
        header Cache-Control "public, max-age=30"
        file_server {
            precompressed gzip
        }
    }

    handle {
        reverse_proxy 127.0.0.1:4601
    }
}
```

## Why not Apache

It works, but its default process/thread-per-connection model is the wrong shape
for many idle connections, which is exactly the traffic a discovery node sees.
nginx and Caddy are event-driven and handle that without a thread each. Use
Apache only if it is already the server you run and know.

## Behind a CDN

The full network directory is the only endpoint worth caching and it is built
for it: the same bytes for everyone until the next version, with an `ETag` and a
`max-age` of half the check interval. Point the CDN at `/v1/directory` without a
query string and full reads stop arriving at the node at all. Requests with
`?since=` are small, per-caller deltas and must not be cached.

Do not cache `/v1/records`, `/health`, or anything under `/v1/peers/`. Never
cache a `POST`.
