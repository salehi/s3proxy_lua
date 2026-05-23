# S3 Signature Proxy (Lua/OpenResty)

A high-performance S3 signature proxy that validates client signatures and re-signs requests for origin S3 servers. Built with OpenResty/Lua for minimal overhead and maximum throughput.

## Architecture

```
┌─────────────┐                                                          
│   Client    │                                                          
│  (signs with│                                                          
│   CLIENT    │                                                          
│ credentials)│                                                          
└──────┬──────┘                                                          
       │ AWS Sig V4                                                      
       │ signed request                                                  
       ▼                                                                  
┌─────────────────────────────────────────────────────────┐             
│                      HAProxy                            │             
│              (Load Balancer + Health Checks)            │             
└──────────────┬──────────────────────┬───────────────────┘             
               │                      │                                  
        ┌──────▼──────┐        ┌──────▼──────┐                          
        │  S3 Proxy   │        │  S3 Proxy   │                          
        │  Server A   │        │  Server B   │                          
        │  (Backup)   │        │  (Primary)  │                          
        │             │        │             │                          
        │ ┌─────────┐ │        │ ┌─────────┐ │                          
        │ │ Verify  │ │        │ │ Verify  │ │                          
        │ │   Sig   │ │        │ │   Sig   │ │                          
        │ └────┬────┘ │        │ └────┬────┘ │                          
        │      │      │        │      │      │                          
        │ ┌────▼────┐ │        │ ┌────▼────┐ │                          
        │ │ Re-sign │ │        │ │ Re-sign │ │                          
        │ │with ORIG│ │        │ │with ORIG│ │                          
        │ └────┬────┘ │        │ └────┬────┘ │                          
        └──────┼──────┘        └──────┼──────┘                          
               │                      │                                  
               └──────────┬───────────┘                                  
                          │ Re-signed with                               
                          │ ORIGIN credentials                           
                          ▼                                              
                   ┌─────────────┐                                       
                   │   Origin    │                                       
                   │ S3 Server A │                                       
                   │  (Minio/S3) │                                       
                   └─────────────┘                                       
                          │                                              
                   ┌─────────────┐                                       
                   │   Origin    │                                       
                   │ S3 Server B │                                       
                   │  (Minio/S3) │                                       
                   └─────────────┘                                       
```

**Flow:**
1. Client signs request with `CLIENT_ACCESS_KEY`/`CLIENT_SECRET_KEY`
2. HAProxy routes to healthy proxy instance
3. Proxy verifies client's AWS Signature V4
4. Proxy re-signs request with origin's `ORIGIN_ACCESS_KEY`/`ORIGIN_SECRET_KEY`
5. Request forwarded to actual S3 server
6. Response streamed back to client

## Quick Start

```bash
# 1. Configure credentials
cp .env.example .env
vim .env

# 2. Start the stack
docker-compose up -d

# 3. Access proxy
curl http://localhost:8080/healthz
```

## Environment Variables

```bash
# Client credentials (what clients use)
CLIENT_ACCESS_KEY=your_client_key
CLIENT_SECRET_KEY=your_client_secret

# Server A credentials
SERVERB_ORIGIN_ACCESS_KEY=s3_servera_key
SERVERB_ORIGIN_SECRET_KEY=s3_servera_secret
SERVERB_ORIGIN_DOMAIN=s3_servera_domain
SERVERB_ORIGIN_HOST=s3_servera_host
SERVERB_ORIGIN_PORT="80"
SERVERB_ORIGIN_SCHEME=http
# Origin health check path (default "/"; e.g. /minio/health/live for MinIO)
SERVERB_ORIGIN_HEALTH_PATH=/

# Server B credentials
SERVERB_ORIGIN_ACCESS_KEY=s3_serverb_key
SERVERB_ORIGIN_SECRET_KEY=s3_serverb_secret
SERVERB_ORIGIN_DOMAIN=s3_serverb_domain
SERVERB_ORIGIN_HOST=s3_serverb_host
SERVERB_ORIGIN_PORT="80"
SERVERB_ORIGIN_SCHEME=http
# Origin health check path (default "/"; e.g. /minio/health/live for MinIO)
SERVERB_ORIGIN_HEALTH_PATH=/

```

## Features

- ✅ **AWS Signature V4** - Full support for presigned URLs
- ✅ **High Availability** - HAProxy with health checks and automatic failover
- ✅ **Dual Backend** - Primary/backup S3 origins
- ✅ **SSL Verification** - Disabled for self-signed certs (configurable)
- ✅ **Streaming** - Direct response streaming for large files
- ✅ **Multi-arch** - Supports amd64 and arm64

## Use Cases

### 1. Credential Rotation
Hide actual S3 credentials from clients. Rotate origin credentials without updating clients.

### 2. Multi-Region Failover
Route requests to different S3 regions based on availability.

### 3. Access Control
Add custom authentication/authorization before S3 access.

### 4. Traffic Monitoring
Log and monitor all S3 access through a single point.

## Generating Signed URLs

```python
# Using sign_s3.py (included)
python sign_s3.py -v 4 --region "" \
  http://localhost:8080 \
  CLIENT_ACCESS_KEY CLIENT_SECRET_KEY \
  bucket-name path/to/object.mp4
```

Or use AWS SDK with proxy endpoint and CLIENT credentials.

## Health Checks

```bash
# Check HAProxy
curl http://localhost:8080/healthz

# Check individual proxies
docker-compose ps
```

## Monitoring

```bash
# View logs
docker-compose logs -f

# Check HAProxy routing
docker-compose logs haproxy

# Watch health checks
docker-compose logs -f | grep healthz
```

## Performance

- **Latency**: <5ms signature verification overhead
- **Throughput**: Handles thousands of concurrent connections
- **Memory**: ~50MB per proxy instance

## Development

```bash
# Build locally
docker-compose build

# Run tests
docker-compose up -d
curl -I http://localhost:8080/healthz
```

## Docker Hub

Image: `s4l3h1/s3proxy_lua`

```bash
docker pull s4l3h1/s3proxy_lua:latest
```

## License

MIT

## Contributing

PRs welcome! This is a production-ready S3 signature proxy optimized for performance.
