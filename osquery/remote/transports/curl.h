/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <curl/curl.h>

#include <osquery/flags.h>

#include "osquery/remote/requests.h"

namespace osquery {

/// TLS server hostname.
DECLARE_string(tls_hostname);

/**
 * @brief HTTPS (TLS) transport using cURL.
 */
class CurlTransport : public Transport {
 public:
  /**
   * @brief Send a simple request to the destination with no parameters
   *
   * @return A status indicating socket, network, or transport success/error.
   * Return code (1) for general connectivity problems, return code (2) for TLS
   * specific errors.
   */
  Status sendRequest() override;

  /**
   * @brief Send a simple request to the destination with parameters
   *
   * @param params A string representing the serialized parameters
   *
   * @return A status indicating socket, network, or transport success/error.
   * Return code (1) for general connectivity problems, return code (2) for TLS
   * specific errors.
   */
  Status sendRequest(const std::string& params, bool compress = false) override;

  /**
   * @brief Class destructor
  */
  virtual ~CurlTransport();

 public:
  CurlTransport();

  CURL *getHandle();

 private:
  /// Testing-only, disable peer verification.
  void disableVerifyPeer() {
    verify_peer_ = false;
  }

 private:
  /// Testing-only, disable peer verification.
  bool verify_peer_;

  /// Linked list of headers that we set on every request.
  struct curl_slist *headers_;

 private:
  /// Storage for the response data.
  std::string response_;

  // Static accessor methods for writing data into our response buffer.
  static size_t write(void *buf, size_t size, size_t nr, void *data);
  size_t mWrite(char *buf, size_t size, size_t nr);

 private:
  /*
  FRIEND_TEST(TLSTransportsTests, test_call);
  FRIEND_TEST(TLSTransportsTests, test_call_with_params);
  FRIEND_TEST(TLSTransportsTests, test_call_verify_peer);
  FRIEND_TEST(TLSTransportsTests, test_call_server_cert_pinning);
  FRIEND_TEST(TLSTransportsTests, test_call_client_auth);
  FRIEND_TEST(TLSTransportsTests, test_call_http);

  friend class TestDistributedPlugin;
  */
};
}
