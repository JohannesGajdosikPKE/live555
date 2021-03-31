set (TARGET UsageEnvironment)

add_library (${TARGET}
  HashTable.cpp
  UsageEnvironment.cpp
  strDup.cpp
)

target_compile_options (${TARGET} PUBLIC -DLIVE555_FORCE_BOOLEAN_TYPE=char)

target_include_directories (${TARGET} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories (${TARGET} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../groupsock/include)

if (WIN32)
  target_compile_options (${TARGET} PUBLIC $<$<NOT:$<CONFIG:Debug>>:-MT>)
  target_compile_options (${TARGET} PUBLIC $<$<CONFIG:Debug>:-MTd>)
else ()
  target_compile_options (${TARGET} PUBLIC -std=c++-11)
endif ()

