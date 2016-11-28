/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/remote/transports/curl.h"

namespace osquery {

CurlTransport::CurlTransport() : verify_peer_(true), headers_(nullptr) {
  std::map<std::string, std::string> headers = {
    {"Connection",   "close"},
    {"Content-Type", serializer_->getContentType()},
    {"Accept",       serializer_->getContentType()},
    {"Host",         FLAGS_tls_hostname},
    {"User-Agent",   "osquery/" + kVersion},
  };

  // Turn the map into a curl-land list of built header lines.
  for (const auto& kv : headers) {
    auto headerLine = kv.first + ": " + kv.second;
    headers_ = curl_slist_append(headers_, headerLine.c_str());
  }
}

CurlTransport::~CurlTransport() {
  curl_slist_free_all(headers_);
}

size_t CurlTransport::write(void *buf, size_t size, size_t nr, void *self) {
  return static_cast<CurlTransport*>(self)->mWrite(static_cast<char*>(buf), size, nr);
}

size_t CurlTransport::mWrite(char *buf, size_t size, size_t nr) {
  response_.append(buf, size * nr);
  return size * nr;
}

CURL *CurlTransport::getHandle() {
  CURL *handle = curl_easy_init();

  // Follow redirects, but only to other HTTPS urls and only 5 of them.
  curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION,  1);
  curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
  curl_easy_setopt(handle, CURLOPT_MAXREDIRS,       5);

  // Explicitly ensure that we're verifying the peer.
  curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1);
  curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2);

  // Use TLSv1.2 if we can.
  curl_easy_setopt(handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

  // TODO: set cipher list properly if we're using OpenSSL

  // Set default headers (built in constructor).
  curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers_);

  // Set the write function to store the response.
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, &CurlTransport::write);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA,     this);

  return nullptr;
}

Status CurlTransport::sendRequest() {
  if (destination_.find("https://") == std::string::npos) {
    return Status(1, "Cannot create TLS request for non-HTTPS protocol URI");
  }

  auto handle = getHandle();
  curl_easy_setopt(handle, CURLOPT_HTTPGET, 1);

  VLOG(1) << "TLS/HTTPS GET request to URI: " << destination_;

  auto res = curl_easy_perform(handle);
  if (res != CURLE_OK) {
    return Status(res == CURLE_SSL_CONNECT_ERROR ? 2 : 1,
        std::string("Request error: ") + curl_easy_strerror(res));
  }

  return serializer_->deserialize(response_, response_params_);
}

Status CurlTransport::sendRequest(const std::string& params, bool compress) {
  if (destination_.find("https://") == std::string::npos) {
    return Status(1, "Cannot create TLS request for non-HTTPS protocol URI");
  }

  auto handle = getHandle();
  curl_easy_setopt(handle, CURLOPT_POSTFIELDS, params.c_str());

  VLOG(1) << "TLS/HTTPS POST request to URI: " << destination_;

  auto res = curl_easy_perform(handle);
  if (res != CURLE_OK) {
    return Status(res == CURLE_SSL_CONNECT_ERROR ? 2 : 1,
        std::string("Request error: ") + curl_easy_strerror(res));
  }

  return serializer_->deserialize(response_, response_params_);
}

}
