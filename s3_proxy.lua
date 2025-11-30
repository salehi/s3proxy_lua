local _M = {}

local resty_sha1 = require "resty.sha1"
local resty_sha256 = require "resty.sha256"
local resty_hmac = require "resty.hmac"
local str = require "resty.string"
local http = require "resty.http"

-- Configuration (set via environment variables)
_M.CLIENT_ACCESS_KEY = os.getenv("CLIENT_ACCESS_KEY") or "your_client_access_key_here"
_M.CLIENT_SECRET_KEY = os.getenv("CLIENT_SECRET_KEY") or "your_client_secret_key_here"
_M.ORIGIN_ACCESS_KEY = os.getenv("ORIGIN_ACCESS_KEY") or "your_origin_access_key_here"
_M.ORIGIN_SECRET_KEY = os.getenv("ORIGIN_SECRET_KEY") or "your_origin_secret_key_here"
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

local function url_decode(str)
    if str then
        str = string.gsub(str, "+", " ")
        str = string.gsub(str, "%%(%x%x)",
            function(h) return string.char(tonumber(h, 16)) end)
    end
    return str
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
    if access_key_id ~= _M.CLIENT_ACCESS_KEY then
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
    
    -- Calculate expected signature
    local expected_signature = calculate_signature_v2(_M.CLIENT_SECRET_KEY, bucket, object_key, expires)
    
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
    if access_key ~= _M.CLIENT_ACCESS_KEY then
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
    
    -- Calculate credential scope (empty region for S3-compatible services)
    local date_stamp = string.sub(amz_date, 1, 8)
    local region = ""
    local credential_scope = string.format("%s/%s/s3/aws4_request", date_stamp, region)
    
    -- Build canonical query string (exclude signature)
    local canonical_parts = {}
    for key, value in pairs(query_params) do
        if key ~= "X-Amz-Signature" then
            local vals = type(value) == "table" and value or {value}
            for _, v in ipairs(vals) do
                table.insert(canonical_parts, 
                    string.format("%s=%s", url_encode(key), url_encode(v)))
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
    
    -- Calculate signature
    local expected_signature = calculate_signature_v4(
        _M.CLIENT_SECRET_KEY, date_stamp, amz_date, 
        credential_scope, canonical_request, region)
    
    return provided_signature == expected_signature, nil
end

-- Generate presigned URL V4
local function generate_presigned_url_v4(endpoint, access_key, secret_key, bucket, object_key, expires_in, region)
    region = region or ""
    
    local host = string.match(endpoint, "://([^/]+)")
    
    local now = ngx.time()
    local datestamp = os.date("!%Y%m%d", now)
    local timestamp = os.date("!%Y%m%dT%H%M%SZ", now)
    
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
            string.format("%s=%s", url_encode(key), url_encode(value)))
    end
    table.sort(canonical_parts)
    local canonical_querystring = table.concat(canonical_parts, "&")
    
    local canonical_headers = string.format("host:%s\n", host)
    local signed_headers = "host"
    local payload_hash = "UNSIGNED-PAYLOAD"
    
    local canonical_request = string.format("GET\n%s\n%s\n%s\n%s\n%s",
        canonical_uri, canonical_querystring, canonical_headers, 
        signed_headers, payload_hash)
    
    local signature = calculate_signature_v4(secret_key, datestamp, timestamp, 
        credential_scope, canonical_request, region)
    
    params["X-Amz-Signature"] = signature
    local url_parts = {}
    for key, value in pairs(params) do
        table.insert(url_parts, string.format("%s=%s", url_encode(key), url_encode(value)))
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
function _M.validate_and_resign_url(request_uri, query_params)
    local is_v4, is_v2 = detect_signature_version(query_params)
    
    if not is_v4 and not is_v2 then
        return string.match(request_uri, "?(.+)$")
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
        if access_key ~= _M.CLIENT_ACCESS_KEY then
            return nil, "Access key mismatch"
        end
        
        local expires_in = tonumber(get_param(query_params, "X-Amz-Expires")) or 3600
        new_url = generate_presigned_url_v4(endpoint, _M.ORIGIN_ACCESS_KEY, 
            _M.ORIGIN_SECRET_KEY, bucket, object_key, expires_in, "")
    elseif is_v2 then
        local access_key_id = get_param(query_params, "AWSAccessKeyId")
        if access_key_id ~= _M.CLIENT_ACCESS_KEY then
            return nil, "Access key mismatch"
        end
        
        local expires_timestamp = tonumber(get_param(query_params, "Expires"))
        local current_timestamp = ngx.time()
        local expires_in = math.max(expires_timestamp - current_timestamp, 60)
        
        new_url = generate_presigned_url_v2(endpoint, _M.ORIGIN_ACCESS_KEY, 
            _M.ORIGIN_SECRET_KEY, bucket, object_key, expires_in)
    end
    
    local query_string = string.match(new_url, "?(.+)$")
    return query_string, nil
end

return _M
