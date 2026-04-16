# CoreDNS

CoreDNS acts as the internal DNS resolver for all containers in this project.
Every service in `docker-compose.yml` is configured with `dns: 172.20.0.53`,
which is the static IP assigned to the `coredns` container on the `proxy-net` network.

## How it works

```
Container query
      │
      ▼
CoreDNS :53  (172.20.0.53)
      │
      ├─► hosts file  ──► match found → return custom A record
      │   /etc/coredns/hosts
      │
      └─► no match → forward to 1.1.1.1 / 8.8.8.8 (public DNS)
```

### Config files

| File | Purpose |
|------|---------|
| `coredns/Corefile` | CoreDNS server configuration |
| `coredns/hosts` | Custom A records (hosts-file format) |

### Network

The `proxy-net` bridge network uses the subnet `172.20.0.0/24`.
CoreDNS is pinned to `172.20.0.53` so the `dns:` entries in all services
always point to the correct container regardless of startup order.

---

## Adding A records

Open [coredns/hosts](hosts) and add a line in hosts-file format:

```
<IP address>   <hostname>
```

**Examples:**

```
# Point a hostname to an external IP
203.0.113.10   storage.internal

# Point to another container's IP (use the container's network IP)
172.20.0.10    myservice.internal

# Multiple aliases on one line
10.0.0.5       primary.internal  primary
```

After saving, restart CoreDNS to apply:

```bash
docker compose restart coredns
```

Verify from any container:

```bash
docker compose exec servera nslookup storage.internal
```

---

## Plugins in use

### `hosts`
Reads `/etc/coredns/hosts` (mounted from `coredns/hosts`) and answers A/AAAA
queries for any hostname listed there. `fallthrough` means unmatched names
are passed to the next plugin instead of returning NXDOMAIN.

### `forward`
Forwards queries that didn't match the hosts file to upstream resolvers
(`1.1.1.1` and `8.8.8.8`). This provides normal internet name resolution
for all containers.

### `cache`
Caches responses for 30 seconds to reduce upstream lookups.

### `log` / `errors`
Logs all queries and errors to stdout (visible via `docker compose logs coredns`).

---

## Adding a full DNS zone (advanced)

If you need SOA/NS records or wildcard DNS for a whole domain, use the
`file` plugin with a zone file instead of (or alongside) the hosts file.

1. Create `coredns/zones/internal.db`:

```dns
$ORIGIN internal.
$TTL 300

@   IN SOA ns1.internal. admin.internal. (
        2024010101 ; serial
        3600       ; refresh
        900        ; retry
        604800     ; expire
        300 )      ; minimum TTL

@   IN NS  ns1.internal.

; A records
ns1         IN A  172.20.0.53
myservice   IN A  172.20.0.10
```

2. Add a block to `coredns/Corefile`:

```
internal:53 {
    file /etc/coredns/zones/internal.db
    log
    errors
}
```

3. Mount the zones directory in `docker-compose.yml`:

```yaml
coredns:
  volumes:
    - ./coredns/Corefile:/etc/coredns/Corefile:ro
    - ./coredns/hosts:/etc/coredns/hosts:ro
    - ./coredns/zones:/etc/coredns/zones:ro
```
