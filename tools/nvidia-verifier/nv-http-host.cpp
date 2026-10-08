// Replaces NVIDIA's libcurl transport in the WebAssembly verifier. Requests go
// to the embedding host, which enforces its own destination allowlist, size
// limits and timeouts. The host owns retries; this client sends each request once.
#include <cstdlib>
#include <string>

#include <emscripten.h>
#include <nlohmann/json.hpp>

#include "nv_attestation/nv_http.h"
#include "nv_attestation/error.h"
#include "nv_attestation/log.h"

EM_ASYNC_JS(int, pi_tee_host_request, (const char* method, const char* url, const char* headers, const char* body, int body_length, char** out_body, int* out_length, int* out_status), {
  const request = Module["piTeeRequest"];
  if (typeof request !== "function") return -1;
  try {
    const response = await request(UTF8ToString(method), UTF8ToString(url), JSON.parse(UTF8ToString(headers)), HEAPU8.slice(body, body + body_length));
    const bytes = response.body;
    if (!(bytes instanceof Uint8Array) || !Number.isInteger(response.status)) return -1;
    const pointer = _malloc(bytes.length + 1);
    if (!pointer) return -1;
    HEAPU8.set(bytes, pointer);
    HEAP32[out_length >> 2] = bytes.length;
    HEAP32[out_status >> 2] = response.status;
    HEAPU32[out_body >> 2] = pointer;
    return 0;
  } catch (error) {
    return -1;
  }
});

namespace nvattestation {

Error NvHttpClient::create(NvHttpClient& out_client, std::string service_key, HttpOptions options) {
    out_client.m_service_key = std::move(service_key);
    out_client.m_options = options;
    return Error::Ok;
}

size_t NvHttpClient::curl_write_callback(void*, size_t, size_t, void*) { return 0; }

Error NvHttpClient::do_request_as_string(const NvRequest& request, long& out_status, std::string& out_response) const {
    out_response.clear();
    const char* method = nullptr;
    switch (request.method) {
        case NvHttpMethod::HTTP_METHOD_GET: method = "GET"; break;
        case NvHttpMethod::HTTP_METHOD_POST: method = "POST"; break;
        case NvHttpMethod::HTTP_METHOD_PUT: method = "PUT"; break;
        case NvHttpMethod::HTTP_METHOD_DELETE: method = "DELETE"; break;
    }
    nlohmann::json headers = nlohmann::json::object();
    for (const auto& header : request.headers) headers[header.first] = header.second;
    if (!m_service_key.empty()) headers["Authorization"] = "Bearer " + m_service_key;
    const std::string encoded_headers = headers.dump();
    char* body = nullptr;
    int length = 0, status = 0;
    if (pi_tee_host_request(method, request.url.c_str(), encoded_headers.c_str(), request.payload.data(),
            static_cast<int>(request.payload.size()), &body, &length, &status) != 0 || body == nullptr) {
        LOG_ERROR("Host HTTP request failed");
        return Error::InternalError;
    }
    out_response.assign(body, static_cast<size_t>(length));
    std::free(body);
    out_status = status;
    if (!is_http_status_2xx(out_status)) LOG_ERROR("HTTP response code: " << out_status);
    return Error::Ok;
}

}
