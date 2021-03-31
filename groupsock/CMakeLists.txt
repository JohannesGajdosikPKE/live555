set (TARGET groupsock)

add_library (${TARGET}
  inet.c
  GroupEId.cpp
  Groupsock.cpp
  GroupsockHelper.cpp
  IOHandlers.cpp
  NetAddress.cpp
  NetInterface.cpp
)

target_compile_options (${TARGET} PUBLIC -DLIVE555_FORCE_BOOLEAN_TYPE=char)

target_include_directories (${TARGET} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories (${TARGET} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../UsageEnvironment/include)

if (WIN32)
  target_compile_options (${TARGET} PRIVATE -DNO_GETIFADDRS)
  target_compile_options (${TARGET} PUBLIC $<$<NOT:$<CONFIG:Debug>>:-MT>)
  target_compile_options (${TARGET} PUBLIC $<$<CONFIG:Debug>:-MTd>)
else ()
  target_compile_options (${TARGET} PUBLIC -std=c++-11)
endif ()

