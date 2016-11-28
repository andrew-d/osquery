set(OSQUERY_REMOTE_FILES
  enroll/enroll.cpp
  serializers/json.cpp
  transports/tls.cpp
  remote.cpp
)

if(OSQUERY_WITH_CURL_TRANSPORT)
  set(OSQUERY_REMOTE_FILES ${OSQUERY_REMOTE_FILES} transports/curl.cpp)
endif()

ADD_OSQUERY_LIBRARY(FALSE osquery_remote ${OSQUERY_REMOTE_FILES})

ADD_OSQUERY_LIBRARY(FALSE osquery_enrollment_plugins
  enroll/plugins/tls.cpp
)

file(GLOB OSQUERY_ENROLLMENT_PLUGIN_TESTS "enrollment/plugins/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_ENROLLMENT_PLUGIN_TESTS})

file(GLOB OSQUERY_REMOTE_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_REMOTE_TESTS})

file(GLOB OSQUERY_REMOTE_COMPONENT_TESTS "*/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_REMOTE_COMPONENT_TESTS})
