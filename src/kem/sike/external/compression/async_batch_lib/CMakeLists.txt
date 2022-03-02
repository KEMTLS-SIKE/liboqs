find_package(sntrup761batch REQUIRED)
find_package(sntrup857batch REQUIRED)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

project("async_batch_provider")

list(APPEND provider_sources kem.c batch.c)

add_library(${provider} STATIC ${provider_sources})
set_property(TARGET ${provider} PROPERTY POSITION_INDEPENDENT_CODE ON)
set_target_properties(${provider} PROPERTIES PREFIX "")

target_include_directories(${provider} PRIVATE ${PROJECT_BINARY_DIR})
target_include_directories(${provider} PRIVATE ${CMAKE_SOURCE_DIR})
#target_include_directories(${provider} PRIVATE ${OPENSSL_INCLUDE_DIR})
target_include_directories(${provider} PRIVATE ${sntrup761batch_INCLUDE_DIRS})
target_include_directories(${provider} PRIVATE ${sntrup857batch_INCLUDE_DIRS})

target_link_libraries(${provider} PUBLIC Threads::Threads)
target_link_libraries(${provider} PUBLIC sntrup761batch)
target_link_libraries(${provider} PUBLIC sntrup857batch)
