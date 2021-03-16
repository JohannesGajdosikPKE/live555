project (live555)

# Recurse into the "Hello" and "Demo" subdirectories. This does not actually
# cause another cmake executable to run. The same process will walk through
# the project's entire directory structure.
add_subdirectory (BasicUsageEnvironment)
add_subdirectory (UsageEnvironment)
add_subdirectory (groupsock)
add_subdirectory (liveMedia)
add_subdirectory (mediaServer)
