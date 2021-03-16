add_executable (mediaServer
  DynamicRTSPServer.cpp
  live555MediaServer.cpp
)

# Link the executable to the Hello library. Since the Hello library has
# public include directories we will use those link directories when building
# helloDemo
target_link_libraries (mediaServer LINK_PUBLIC BasicUsageEnvironment UsageEnvironment groupsock liveMedia ws2_32)

