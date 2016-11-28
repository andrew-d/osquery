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

#if OSQUERY_WITH_TLS_TRANSPORT
#include "tls.h"

#define DefaultTransport TLSTransport
#endif

#if OSQUERY_WITH_CURL_TRANSPORT
#include "curl.h"

#define DefaultTransport CurlTransport
#endif
