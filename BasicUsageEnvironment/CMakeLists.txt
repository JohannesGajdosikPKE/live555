add_library (BasicUsageEnvironment
  BasicHashTable.cpp
  BasicTaskScheduler.cpp
  BasicTaskScheduler0.cpp
  BasicUsageEnvironment.cpp
  BasicUsageEnvironment0.cpp
  DelayQueue.cpp
)

target_include_directories (BasicUsageEnvironment PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories (BasicUsageEnvironment PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../groupsock/include)
target_include_directories (BasicUsageEnvironment PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../UsageEnvironment/include)
