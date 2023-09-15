set (TARGET mediaServer)

project (${TARGET} DESCRIPTION "Live555 Media Server")

add_executable (${TARGET}
  DynamicRTSPServer.cpp
  live555MediaServer.cpp
)

target_compile_options (${TARGET} PUBLIC -DLIVE555_FORCE_BOOLEAN_TYPE=char)
target_compile_options(${TARGET} PUBLIC -DNO_OPENSSL)

target_include_directories(${TARGET} PUBLIC ../groupsock/include)
target_include_directories(${TARGET} PUBLIC ../UsageEnvironment/include)
target_include_directories(${TARGET} PUBLIC ../BasicUsageEnvironment/include)
target_include_directories(${TARGET} PUBLIC ../liveMedia/include)


if (WIN32)
  target_compile_options(${TARGET} PRIVATE -DLIVE555_EXPORT=__declspec\(dllimport\))
  target_compile_options (${TARGET} PUBLIC $<$<NOT:$<CONFIG:Debug>>:-MD>)
  target_compile_options (${TARGET} PUBLIC $<$<CONFIG:Debug>:-MDd>)
else ()
  target_compile_options (${TARGET} PUBLIC -std=c++-11)
endif ()

target_link_libraries (${TARGET} $<$<CONFIG:Debug>:../../libLive555/build/Debug/Live555d>)
target_link_libraries (${TARGET} $<$<CONFIG:Release>:../../libLive555/build/Release/Live555>)
target_link_libraries (${TARGET} $<$<CONFIG:RelWithDebInfo>:../../libLive555/build/RelWithDebInfo/Live555>)

