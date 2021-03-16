add_library (UsageEnvironment
  HashTable.cpp
  UsageEnvironment.cpp
  strDup.cpp
)

target_include_directories (UsageEnvironment PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories (UsageEnvironment PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../groupsock/include)
