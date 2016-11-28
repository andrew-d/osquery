option(OSQUERY_WITH_TLS_TRANSPORT "Use default TLS transport" ON)
option(OSQUERY_WITH_CURL_TRANSPORT "Use cURL transport for TLS" OFF)

if(OSQUERY_WITH_TLS_TRANSPORT)
  add_definitions(-DOSQUERY_WITH_TLS_TRANSPORT=1)
  add_definitions(-DOSQUERY_WITH_CURL_TRANSPORT=0)

elseif(OSQUERY_WITH_CURL_TRANSPORT)
  set(OSQUERY_REMOTE_FILES ${OSQUERY_REMOTE_FILES} transports/curl.cpp)
  add_definitions(-DOSQUERY_WITH_TLS_TRANSPORT=0)
  add_definitions(-DOSQUERY_WITH_CURL_TRANSPORT=1)

else()
  message(FATAL_ERROR "No transport enabled - you must select one")

endif()
