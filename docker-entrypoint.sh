#!/bin/sh
set -e

# Set defaults if not provided
: ${ORIGIN_HOST:=s3.example.com}
: ${ORIGIN_PORT:=443}
: ${ORIGIN_SCHEME:=https}
: ${PORT:=8080}

echo "Rendering nginx configuration..."
echo "ORIGIN_HOST: $ORIGIN_HOST"
echo "ORIGIN_PORT: $ORIGIN_PORT"
echo "ORIGIN_SCHEME: $ORIGIN_SCHEME"
echo "PORT: $PORT"

# Render nginx config using envsubst
envsubst '${ORIGIN_HOST} ${ORIGIN_PORT} ${ORIGIN_SCHEME} ${PORT}' \
    < /usr/local/openresty/nginx/conf/nginx.conf.template \
    > /usr/local/openresty/nginx/conf/nginx.conf

echo "Configuration rendered successfully"

# Test nginx configuration
/usr/local/openresty/bin/openresty -t

# Execute the command passed to the container
exec "$@"
