set (TARGET BasicUsageEnvironment)

add_library (${TARGET}
  BasicHashTable.cpp
  BasicTaskScheduler.cpp
  BasicTaskScheduler0.cpp
  BasicUsageEnvironment.cpp
  BasicUsageEnvironment0.cpp
  DelayQueue.cpp
)

target_compile_options (${TARGET} PUBLIC -DLIVE555_FORCE_BOOLEAN_TYPE=char)

target_include_directories (${TARGET} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories (${TARGET} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../groupsock/include)
target_include_directories (${TARGET} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../UsageEnvironment/include)

if (WIN32)
  target_compile_options (${TARGET} PUBLIC $<$<NOT:$<CONFIG:Debug>>:-MT>)
  target_compile_options (${TARGET} PUBLIC $<$<CONFIG:Debug>:-MTd>)
else ()
  target_compile_options (${TARGET} PUBLIC -std=c++-11)
endif ()

