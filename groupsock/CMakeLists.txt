add_library (groupsock
  inet.c
  GroupEId.cpp
  Groupsock.cpp
  GroupsockHelper.cpp
  IOHandlers.cpp
  NetAddress.cpp
  NetInterface.cpp
)

if (WIN32)
  target_compile_options(groupsock PRIVATE -DNO_GETIFADDRS)
endif ()

target_include_directories (groupsock PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories (groupsock PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../UsageEnvironment/include)
