FROM openresty/openresty:bookworm-fat

# Install dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        gettext-base \
        curl \
        perl \
    && rm -rf /var/lib/apt/lists/*

# Install lua-resty libraries using opm
RUN /usr/local/openresty/bin/opm get ledgetech/lua-resty-http

# Install lua-resty-string manually (simpler - just copy files)
RUN cd /tmp \
    && git clone https://github.com/openresty/lua-resty-string.git \
    && cd lua-resty-string \
    && cp -r lib/resty /usr/local/openresty/lualib/ \
    && cd / \
    && rm -rf /tmp/lua-resty-string

# Install lua-resty-hmac manually
RUN cd /tmp \
    && git clone https://github.com/jkeys089/lua-resty-hmac.git \
    && cd lua-resty-hmac \
    && cp -r lib/resty /usr/local/openresty/lualib/ \
    && cd / \
    && rm -rf /tmp/lua-resty-hmac

# Create directories
RUN mkdir -p /usr/local/openresty/nginx/lua

# Copy Lua module
COPY s3_proxy.lua /usr/local/openresty/nginx/lua/

# Copy nginx config template
COPY nginx.conf.template /usr/local/openresty/nginx/conf/

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Environment variables with defaults
ENV CLIENT_ACCESS_KEY=your_client_access_key_here \
    CLIENT_SECRET_KEY=your_client_secret_key_here \
    ORIGIN_ACCESS_KEY=your_origin_access_key_here \
    ORIGIN_SECRET_KEY=your_origin_secret_key_here \
    ORIGIN_DOMAIN=s3.example.com \
    ORIGIN_SCHEME=https \
    ORIGIN_HOST=s3.example.com \
    ORIGIN_PORT=443 \
    PORT=8080

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
