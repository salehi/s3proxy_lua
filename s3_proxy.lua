local _M = {}

local resty_sha1 = require "resty.sha1"
local resty_sha256 = require "resty.sha256"
local resty_hmac = require "resty.hmac"
local str = require "resty.string"
local http = require "resty.http"

-- Secrets: module-level locals, not accessible via the module table
local CLIENT_ACCESS_KEY = os.getenv("CLIENT_ACCESS_KEY") or "your_client_access_key_here"
local CLIENT_SECRET_KEY = os.getenv("CLIENT_SECRET_KEY") or "your_client_secret_key_here"
local ORIGIN_ACCESS_KEY = os.getenv("ORIGIN_ACCESS_KEY") or "your_origin_access_key_here"
local ORIGIN_SECRET_KEY = os.getenv("ORIGIN_SECRET_KEY") or "your_origin_secret_key_here"
local ORIGIN_REGION     = os.getenv("ORIGIN_REGION")     or "us-east-1"

-- Non-secret config: exposed for callers (e.g. nginx.conf reads these)
_M.ORIGIN_DOMAIN = os.getenv("ORIGIN_DOMAIN") or "s3.example.com"
_M.ORIGIN_SCHEME = os.getenv("ORIGIN_SCHEME") or "https"

-- URL encoding
local function url_encode(str)
    if str then
        str = string.gsub(str, "\n", "\r\n")
        str = string.gsub(str, "([^%w%-%.%_%~ ])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
        str = string.gsub(str, " ", "+")
    end
    return str
end

-- AWS V4 URI encoding: percent-encode everything except unreserved chars (RFC 3986)
-- Spaces become %20, not +
-- Note: string.gsub returns (string, count); we discard the count so callers
-- receive exactly one value (prevents table.insert mis-interpreting 2 returns).
-- ngx.req.get_uri_args() returns boolean true for valueless params (e.g. ?location);
-- those canonicalise to an empty value, so we treat true as "".
local function aws_encode(s)
    if not s or s == true then return "" end
    local result, _ = string.gsub(tostring(s), "([^%w%-%.%_%~])",
        function(c) return string.format("%%%02X", string.byte(c)) end)
    return result
end

-- SHA256 hex digest
local function sha256_hex(data)
    local sha256 = resty_sha256:new()
    sha256:update(data or "")
    return str.to_hex(sha256:final())
end

-- Export sha256_hex for use in nginx.conf
_M.sha256_hex = sha256_hex

local function url_decode(str)
    if str then
        str = string.gsub(str, "+", " ")
        str = string.gsub(str, "%%(%x%x)",
            function(h) return string.char(tonumber(h, 16)) end)
    end
    return str
end

-- Format current UTC time without blocking the event loop.
-- ngx.utctime() returns "YYYY/MM/DD HH:MM:SS" with no libc mutex.
-- Returns datestamp ("YYYYMMDD") and timestamp ("YYYYMMDDTHHMMSSz").
local function utc_format_now()
    local s = ngx.utctime()
    local date = string.sub(s, 1, 4) .. string.sub(s, 6, 7) .. string.sub(s, 9, 10)
    local ts   = date .. "T"
               .. string.sub(s, 12, 13) .. string.sub(s, 15, 16) .. string.sub(s, 18, 19) .. "Z"
    return date, ts
end

-- Get first value from param (handles both string and table)
local function get_param(params, key)
    local val = params[key]
    if type(val) == "table" then
        return val[1]
    end
    return val
end

-- Detect signature version
local function detect_signature_version(query_params)
    local is_v4 = query_params["X-Amz-Signature"] ~= nil
    local is_v2 = query_params["Signature"] ~= nil and (query_params["AWSAccessKeyId"] ~= nil or query_params["Expires"] ~= nil)
    return is_v4, is_v2
end

-- Calculate signature V2
local function calculate_signature_v2(secret_key, bucket, object_key, expiration)
    local string_to_sign = string.format("GET\n\n\n%s\n/%s/%s", expiration, bucket, object_key)
    
    local hmac = require "resty.hmac"
    local h = hmac:new(secret_key, hmac.ALGOS.SHA1)
    if not h then
        return nil
    end
    local ok = h:update(string_to_sign)
    if not ok then
        return nil
    end
    local signature = h:final()
    
    return ngx.encode_base64(signature)
end

-- Calculate signature V4
local function calculate_signature_v4(secret_key, datestamp, timestamp, credential_scope, canonical_request, region)
    region = region or ""
    
    -- Hash canonical request
    local sha256 = resty_sha256:new()
    sha256:update(canonical_request)
    local canonical_hash = str.to_hex(sha256:final())
    
    -- String to sign
    local algorithm = "AWS4-HMAC-SHA256"
    local string_to_sign = string.format("%s\n%s\n%s\n%s", 
        algorithm, timestamp, credential_scope, canonical_hash)
    
    -- Signing key derivation
    local function hmac_sha256(key, data)
        local hmac = require "resty.hmac"
        local h = hmac:new(key, hmac.ALGOS.SHA256)
        if not h then
            return nil
        end
        local ok = h:update(data)
        if not ok then
            return nil
        end
        return h:final()
    end
    
    local kDate = hmac_sha256("AWS4" .. secret_key, datestamp)
    if not kDate then
        return nil
    end
    
    local kRegion = hmac_sha256(kDate, region)
    if not kRegion then
        return nil
    end
    
    local kService = hmac_sha256(kRegion, "s3")
    if not kService then
        return nil
    end
    
    local kSigning = hmac_sha256(kService, "aws4_request")
    if not kSigning then
        return nil
    end
    
    -- Final signature
    local signature = hmac_sha256(kSigning, string_to_sign)
    if not signature then
        return nil
    end
    
    return str.to_hex(signature)
end

-- Verify signature V2
function _M.verify_signature_v2(request_uri, query_params, headers)
    local access_key_id = get_param(query_params, "AWSAccessKeyId")
    if access_key_id ~= CLIENT_ACCESS_KEY then
        return false, "Access key mismatch"
    end
    
    local provided_signature = get_param(query_params, "Signature")
    local expires = get_param(query_params, "Expires")
    
    if not provided_signature or not expires then
        return false, "Missing signature or expires"
    end
    
    -- Extract bucket and object from path
    local path = string.match(request_uri, "^([^?]+)")
    local path_parts = {}
    for part in string.gmatch(path:gsub("^/", ""), "[^/]+") do
        table.insert(path_parts, part)
    end
    
    if #path_parts < 2 then
        return false, "Invalid S3 path"
    end
    
    local bucket = path_parts[1]
    local object_key = table.concat(path_parts, "/", 2)
    
    -- Reject expired URLs
    if tonumber(expires) < ngx.time() then
        return false, "Request expired"
    end

    -- Calculate expected signature
    local expected_signature = calculate_signature_v2(CLIENT_SECRET_KEY, bucket, object_key, expires)

    return provided_signature == expected_signature, nil
end

-- Verify signature V4
function _M.verify_signature_v4(request_uri, query_params, headers, method)
    local credential = get_param(query_params, "X-Amz-Credential")
    if not credential then
        return false, "Missing credential"
    end
    
    -- Extract access key from credential
    local access_key = string.match(credential, "^([^/]+)")
    if access_key ~= CLIENT_ACCESS_KEY then
        return false, "Access key mismatch"
    end
    
    local algorithm = get_param(query_params, "X-Amz-Algorithm")
    if algorithm ~= "AWS4-HMAC-SHA256" then
        return false, "Invalid algorithm"
    end
    
    local provided_signature = get_param(query_params, "X-Amz-Signature")
    local amz_date = get_param(query_params, "X-Amz-Date")
    local signed_headers = get_param(query_params, "X-Amz-SignedHeaders") or "host"
    
    if not provided_signature or not amz_date then
        return false, "Missing signature or date"
    end
    
    -- Extract path
    local path = string.match(request_uri, "^([^?]+)")
    local host = headers["host"] or headers["Host"]
    
    -- Extract region from credential: ACCESS_KEY/DATE/REGION/s3/aws4_request
    local date_stamp = string.sub(amz_date, 1, 8)
    local cred_parts = {}
    for part in string.gmatch(credential, "[^/]+") do
        table.insert(cred_parts, part)
    end
    local region = cred_parts[3] or "us-east-1"
    local credential_scope = string.format("%s/%s/s3/aws4_request", date_stamp, region)
    
    -- Build canonical query string (exclude signature)
    local canonical_parts = {}
    for key, value in pairs(query_params) do
        if key ~= "X-Amz-Signature" then
            local vals = type(value) == "table" and value or {value}
            for _, v in ipairs(vals) do
                table.insert(canonical_parts,
                    string.format("%s=%s", aws_encode(key), aws_encode(v)))
            end
        end
    end
    table.sort(canonical_parts)
    local canonical_querystring = table.concat(canonical_parts, "&")
    
    -- Canonical headers and request
    local canonical_headers = string.format("host:%s\n", host)
    local payload_hash = "UNSIGNED-PAYLOAD"
    local canonical_request = string.format("%s\n%s\n%s\n%s\n%s\n%s",
        method or "GET", path, canonical_querystring, 
        canonical_headers, signed_headers, payload_hash)
    
    -- Reject expired presigned URLs (X-Amz-Expires is seconds since X-Amz-Date)
    local amz_expires = tonumber(get_param(query_params, "X-Amz-Expires"))
    if amz_expires then
        -- Parse X-Amz-Date: YYYYMMDDTHHMMSSz
        local yr, mo, dy, hr, mn, sc = string.match(amz_date, "^(%d%d%d%d)(%d%d)(%d%d)T(%d%d)(%d%d)(%d%d)Z$")
        if yr then
            local signed_at = os.time({year=tonumber(yr), month=tonumber(mo), day=tonumber(dy),
                                       hour=tonumber(hr), min=tonumber(mn), sec=tonumber(sc)})
            if ngx.time() > signed_at + amz_expires then
                return false, "Request expired"
            end
        end
    end

    -- Calculate signature
    local expected_signature = calculate_signature_v4(
        CLIENT_SECRET_KEY, date_stamp, amz_date,
        credential_scope, canonical_request, region)

    return provided_signature == expected_signature, nil
end

-- Generate presigned URL V4
local function generate_presigned_url_v4(endpoint, access_key, secret_key, bucket, object_key, expires_in, region, method)
    region = region or ""
    method = method or "GET"
    
    local host = string.match(endpoint, "://([^/]+)")
    
    local datestamp, timestamp = utc_format_now()
    
    local credential_scope = string.format("%s/%s/s3/aws4_request", datestamp, region)
    
    local params = {
        ["X-Amz-Algorithm"] = "AWS4-HMAC-SHA256",
        ["X-Amz-Credential"] = string.format("%s/%s", access_key, credential_scope),
        ["X-Amz-Date"] = timestamp,
        ["X-Amz-Expires"] = tostring(expires_in),
        ["X-Amz-SignedHeaders"] = "host"
    }
    
    local canonical_uri = string.format("/%s/%s", bucket, object_key)
    
    local canonical_parts = {}
    for key, value in pairs(params) do
        table.insert(canonical_parts,
            string.format("%s=%s", aws_encode(key), aws_encode(value)))
    end
    table.sort(canonical_parts)
    local canonical_querystring = table.concat(canonical_parts, "&")

    local canonical_headers = string.format("host:%s\n", host)
    local signed_headers = "host"
    local payload_hash = "UNSIGNED-PAYLOAD"

    local canonical_request = string.format("%s\n%s\n%s\n%s\n%s\n%s",
        method,
        canonical_uri, canonical_querystring, canonical_headers,
        signed_headers, payload_hash)

    local signature = calculate_signature_v4(secret_key, datestamp, timestamp,
        credential_scope, canonical_request, region)

    params["X-Amz-Signature"] = signature
    local url_parts = {}
    for key, value in pairs(params) do
        table.insert(url_parts, string.format("%s=%s", aws_encode(key), aws_encode(value)))
    end
    table.sort(url_parts)
    
    local url = string.format("%s/%s/%s", endpoint, bucket, 
        url_encode(object_key):gsub("%%2F", "/"))
    
    return url .. "?" .. table.concat(url_parts, "&")
end

-- Generate presigned URL V2
local function generate_presigned_url_v2(endpoint, access_key, secret_key, bucket, object_key, expires_in)
    local expiration = ngx.time() + expires_in
    local signature_b64 = calculate_signature_v2(secret_key, bucket, object_key, expiration)
    
    local url = string.format("%s/%s/%s", endpoint, bucket, url_encode(object_key):gsub("%%2F", "/"))
    local params = string.format("AWSAccessKeyId=%s&Expires=%d&Signature=%s",
        url_encode(access_key), expiration, url_encode(signature_b64))
    
    return url .. "?" .. params
end

-- Validate and re-sign URL
function _M.validate_and_resign_url(request_uri, query_params, method)
    local is_v4, is_v2 = detect_signature_version(query_params)
    
    if not is_v4 and not is_v2 then
        return nil, "unsigned request"
    end
    
    -- Extract bucket and object from path
    local path = string.match(request_uri, "^([^?]+)")
    local path_parts = {}
    for part in string.gmatch(path:gsub("^/", ""), "[^/]+") do
        table.insert(path_parts, part)
    end
    
    if #path_parts < 2 then
        return nil, "Invalid S3 path"
    end
    
    local bucket = path_parts[1]
    local object_key = table.concat(path_parts, "/", 2)
    
    local endpoint = string.format("%s://%s", _M.ORIGIN_SCHEME, _M.ORIGIN_DOMAIN)
    local new_url
    
    if is_v4 then
        local credential = get_param(query_params, "X-Amz-Credential")
        if not credential then
            return nil, "Missing credential"
        end
        
        local access_key = string.match(credential, "^([^/]+)")
        if access_key ~= CLIENT_ACCESS_KEY then
            return nil, "Access key mismatch"
        end
        
        local expires_in = tonumber(get_param(query_params, "X-Amz-Expires")) or 3600
        new_url = generate_presigned_url_v4(endpoint, ORIGIN_ACCESS_KEY,
            ORIGIN_SECRET_KEY, bucket, object_key, expires_in, ORIGIN_REGION, method)
    elseif is_v2 then
        local access_key_id = get_param(query_params, "AWSAccessKeyId")
        if access_key_id ~= CLIENT_ACCESS_KEY then
            return nil, "Access key mismatch"
        end
        
        local expires_timestamp = tonumber(get_param(query_params, "Expires"))
        local current_timestamp = ngx.time()
        local expires_in = math.max(expires_timestamp - current_timestamp, 60)
        
        new_url = generate_presigned_url_v2(endpoint, ORIGIN_ACCESS_KEY, 
            ORIGIN_SECRET_KEY, bucket, object_key, expires_in)
    end
    
    local query_string = string.match(new_url, "?(.+)$")
    return query_string, nil
end

-- Detect Authorization-header mode (AWS Signature V4, header-based auth)
function _M.detect_auth_header(headers)
    local auth = headers["authorization"]
    if auth and string.match(auth, "^AWS4%-HMAC%-SHA256") then
        return true
    end
    return false
end

-- Verify the CLIENT signature on an Authorization-header request and produce a
-- new Authorization header signed with ORIGIN credentials.
--
-- Returns: ok, new_auth_header, new_amz_date, payload_hash, err
function _M.verify_and_resign_auth_header(method, path, query_params, headers, body)
    local auth = headers["authorization"]
    if not auth then
        return false, nil, nil, nil, "Missing Authorization header"
    end

    -- Parse the three components from the Authorization header
    local credential   = string.match(auth, "Credential=([^,%s]+)")
    local signed_h_str = string.match(auth, "SignedHeaders=([^,%s]+)")
    local provided_sig = string.match(auth, "Signature=([a-f0-9]+)")

    if not credential or not signed_h_str or not provided_sig then
        return false, nil, nil, nil, "Malformed Authorization header"
    end

    -- Credential format: ACCESS_KEY/DATE/REGION/s3/aws4_request
    local cred_parts = {}
    for part in string.gmatch(credential, "[^/]+") do
        table.insert(cred_parts, part)
    end
    if #cred_parts < 5 then
        return false, nil, nil, nil, "Malformed credential"
    end
    local access_key = cred_parts[1]
    local date_stamp = cred_parts[2]
    local region     = cred_parts[3]

    if access_key ~= CLIENT_ACCESS_KEY then
        return false, nil, nil, nil, "Access key mismatch"
    end

    local amz_date = headers["x-amz-date"]
    if not amz_date then
        return false, nil, nil, nil, "Missing X-Amz-Date header"
    end

    -- Payload hash: use client-provided value or compute from body
    local payload_hash = headers["x-amz-content-sha256"]
    if not payload_hash then
        payload_hash = sha256_hex(body or "")
    end

    -- Build signed headers list (already sorted and lowercased per spec)
    local signed_h_list = {}
    for h in string.gmatch(signed_h_str, "[^;]+") do
        table.insert(signed_h_list, h)
    end

    -- Canonical URI: percent-encode each path segment
    local canonical_uri
    if path == "" or path == "/" then
        canonical_uri = "/"
    else
        local segments = {}
        for segment in string.gmatch(path, "[^/]+") do
            table.insert(segments, aws_encode(segment))
        end
        canonical_uri = "/" .. table.concat(segments, "/")
        if string.sub(path, -1) == "/" then
            canonical_uri = canonical_uri .. "/"
        end
    end

    -- Canonical query string: sort by encoded key
    local qparts = {}
    for key, value in pairs(query_params) do
        local vals = type(value) == "table" and value or {value}
        for _, v in ipairs(vals) do
            table.insert(qparts, aws_encode(key) .. "=" .. aws_encode(v))
        end
    end
    table.sort(qparts)
    local canonical_qs = table.concat(qparts, "&")

    -- Helper: build canonical headers string for a given (lowercase) headers table
    local function build_canonical_headers(hdrs)
        local s = ""
        for _, h_name in ipairs(signed_h_list) do
            local val = hdrs[h_name] or ""
            val = string.match(tostring(val), "^%s*(.-)%s*$")
            s = s .. h_name .. ":" .. val .. "\n"
        end
        return s
    end

    -- Verify CLIENT signature
    local client_canon_headers = build_canonical_headers(headers)
    local client_canon_req = string.format("%s\n%s\n%s\n%s\n%s\n%s",
        method, canonical_uri, canonical_qs,
        client_canon_headers, signed_h_str, payload_hash)

    local credential_scope = string.format("%s/%s/s3/aws4_request", date_stamp, region)
    local expected_sig = calculate_signature_v4(
        CLIENT_SECRET_KEY, date_stamp, amz_date,
        credential_scope, client_canon_req, region)

    if expected_sig ~= provided_sig then
        return false, nil, nil, nil, "Signature mismatch"
    end

    -- Re-sign with ORIGIN credentials using a fresh timestamp
    local new_date, new_ts = utc_format_now()
    local new_cred_scope = string.format("%s/%s/s3/aws4_request", new_date, region)

    -- Build ORIGIN headers map: copy original (lowercase) then override host + date
    local origin_hdrs = {}
    for k, v in pairs(headers) do
        origin_hdrs[k:lower()] = v
    end
    origin_hdrs["host"]      = _M.ORIGIN_DOMAIN
    origin_hdrs["x-amz-date"] = new_ts

    local origin_canon_headers = build_canonical_headers(origin_hdrs)
    local origin_canon_req = string.format("%s\n%s\n%s\n%s\n%s\n%s",
        method, canonical_uri, canonical_qs,
        origin_canon_headers, signed_h_str, payload_hash)

    local new_sig = calculate_signature_v4(
        ORIGIN_SECRET_KEY, new_date, new_ts,
        new_cred_scope, origin_canon_req, region)

    if not new_sig then
        return false, nil, nil, nil, "Failed to compute origin signature"
    end

    local new_auth = string.format(
        "AWS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s",
        ORIGIN_ACCESS_KEY, new_cred_scope, signed_h_str, new_sig)

    return true, new_auth, new_ts, payload_hash, nil
end

return _M
