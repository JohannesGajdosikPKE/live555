set (TARGET mediaServer)

add_executable (${TARGET}
  DynamicRTSPServer.cpp
  live555MediaServer.cpp
)

target_compile_options (${TARGET} PUBLIC -DLIVE555_FORCE_BOOLEAN_TYPE=char)

if (WIN32)
  target_compile_options (${TARGET} PUBLIC $<$<NOT:$<CONFIG:Debug>>:-MT>)
  target_compile_options (${TARGET} PUBLIC $<$<CONFIG:Debug>:-MTd>)
else ()
  target_compile_options (${TARGET} PUBLIC -std=c++-11)
endif ()

target_link_libraries (${TARGET} LINK_PUBLIC BasicUsageEnvironment UsageEnvironment groupsock liveMedia ws2_32)

