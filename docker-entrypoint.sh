#!/bin/sh
set -e

# Set defaults if not provided
: ${ORIGIN_HOST:=s3.example.com}
: ${ORIGIN_PORT:=443}
: ${ORIGIN_SCHEME:=https}
: ${PORT:=8080}

# Derive resolver from /etc/resolv.conf (works in Docker, k8s, bare-metal)
RESOLVER=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf)
: ${RESOLVER:=8.8.8.8}
export RESOLVER

echo "Rendering nginx configuration..."
echo "ORIGIN_HOST: $ORIGIN_HOST"
echo "ORIGIN_PORT: $ORIGIN_PORT"
echo "ORIGIN_SCHEME: $ORIGIN_SCHEME"
echo "PORT: $PORT"
echo "RESOLVER: $RESOLVER"

# Render nginx config using envsubst
envsubst '${ORIGIN_HOST} ${ORIGIN_PORT} ${ORIGIN_SCHEME} ${PORT} ${RESOLVER}' \
    < /usr/local/openresty/nginx/conf/nginx.conf.template \
    > /usr/local/openresty/nginx/conf/nginx.conf

echo "Configuration rendered successfully"

# Test nginx configuration
/usr/local/openresty/bin/openresty -t

# Execute the command passed to the container
exec "$@"
