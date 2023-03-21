cmake_minimum_required(VERSION 3.0.0)
project(lightssl VERSION 0.1.0)

include(CTest)
enable_testing()

set(CMAKE_CONFIGURATION_TYPES Release)

set(CMAKE_DEBUG_POSTFIX debug)
set(CMAKE_RELEASE_POSTFIX release)

# Pthread
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wno-unused-variable -Wno-unused-function -Wall -Wextra -Wno-unused-parameter -pedantic -pthread -O3")

add_library(lighthash OBJECT src/lighthash.c)
add_library(lightkeys OBJECT src/lightkeys.c)
add_library(lightcrypto OBJECT src/lightcrypto.c)
add_library(lightciphers OBJECT src/lightciphers.c)

if ( CMAKE_BUILD_TYPE STREQUAL Debug )
add_executable(${CMAKE_DEBUG_POSTFIX}_test_hash3 src/tests/test_lighthash3.c)
add_executable(${CMAKE_DEBUG_POSTFIX}_test_hash3_shake src/tests/test_lighthash3_shake.c)
add_executable(${CMAKE_DEBUG_POSTFIX}_test_ciphers src/tests/test_lightciphers.c)
add_executable(${CMAKE_DEBUG_POSTFIX}_test_crypto src/tests/test_lightcrypto.c)
add_executable(${CMAKE_DEBUG_POSTFIX}_test_crypto_cli src/tests/test_lightcrypto_cli.c)
add_executable(${CMAKE_DEBUG_POSTFIX}_test_crypto_srv src/tests/test_lightcrypto_srv.c)
add_executable(${CMAKE_DEBUG_POSTFIX}_test_keys src/tests/test_lightkeys.c)

target_link_libraries(${CMAKE_DEBUG_POSTFIX}_test_hash3 PUBLIC lighthash PRIVATE m)
target_link_libraries(${CMAKE_DEBUG_POSTFIX}_test_hash3_shake PUBLIC lighthash PRIVATE m)
target_link_libraries(${CMAKE_DEBUG_POSTFIX}_test_ciphers PUBLIC lightciphers PRIVATE m)
target_link_libraries(${CMAKE_DEBUG_POSTFIX}_test_crypto PUBLIC lightcrypto PRIVATE m)
target_link_libraries(${CMAKE_DEBUG_POSTFIX}_test_crypto_cli PUBLIC lightcrypto PRIVATE m)
target_link_libraries(${CMAKE_DEBUG_POSTFIX}_test_crypto_srv PUBLIC lightcrypto PRIVATE m)
target_link_libraries(${CMAKE_DEBUG_POSTFIX}_test_keys PUBLIC lightkeys PRIVATE m)

add_test(NAME ${CMAKE_DEBUG_POSTFIX}_test_hash3 COMMAND ${CMAKE_DEBUG_POSTFIX}_test_hash3)
add_test(NAME ${CMAKE_DEBUG_POSTFIX}_test_hash3_shake COMMAND ${CMAKE_DEBUG_POSTFIX}_test_hash3_shake)
add_test(NAME ${CMAKE_DEBUG_POSTFIX}_test_ciphers COMMAND ${CMAKE_DEBUG_POSTFIX}_test_ciphers)
add_test(NAME ${CMAKE_DEBUG_POSTFIX}_test_crypto COMMAND ${CMAKE_DEBUG_POSTFIX}_test_crypto)
add_test(NAME ${CMAKE_DEBUG_POSTFIX}_test_keys COMMAND ${CMAKE_DEBUG_POSTFIX}_test_keys)
endif()

if ( CMAKE_BUILD_TYPE STREQUAL Release )
add_executable(${CMAKE_RELEASE_POSTFIX}_test_hash3 src/tests/test_lighthash3.c)
add_executable(${CMAKE_RELEASE_POSTFIX}_test_hash3_shake src/tests/test_lighthash3_shake.c)
add_executable(${CMAKE_RELEASE_POSTFIX}_test_ciphers src/tests/test_lightciphers.c)
add_executable(${CMAKE_RELEASE_POSTFIX}_test_crypto src/tests/test_lightcrypto.c)
add_executable(${CMAKE_RELEASE_POSTFIX}_test_crypto_cli src/tests/test_lightcrypto_cli.c)
add_executable(${CMAKE_RELEASE_POSTFIX}_test_crypto_srv src/tests/test_lightcrypto_srv.c)
add_executable(${CMAKE_RELEASE_POSTFIX}_test_keys src/tests/test_lightkeys.c)

target_link_libraries(${CMAKE_RELEASE_POSTFIX}_test_hash3 PUBLIC lighthash PRIVATE m)
target_link_libraries(${CMAKE_RELEASE_POSTFIX}_test_hash3_shake PUBLIC lighthash PRIVATE m)
target_link_libraries(${CMAKE_RELEASE_POSTFIX}_test_ciphers PUBLIC lightciphers PRIVATE m)
target_link_libraries(${CMAKE_RELEASE_POSTFIX}_test_crypto PUBLIC lightcrypto PRIVATE m)
target_link_libraries(${CMAKE_RELEASE_POSTFIX}_test_crypto_cli PUBLIC lightcrypto PRIVATE m)
target_link_libraries(${CMAKE_RELEASE_POSTFIX}_test_crypto_srv PUBLIC lightcrypto PRIVATE m)
target_link_libraries(${CMAKE_RELEASE_POSTFIX}_test_keys PUBLIC lightkeys PRIVATE m)


add_test(NAME ${CMAKE_RELEASE_POSTFIX}_test_hash3 COMMAND ${CMAKE_RELEASE_POSTFIX}_test_hash3)
add_test(NAME ${CMAKE_RELEASE_POSTFIX}_test_hash3_shake COMMAND ${CMAKE_RELEASE_POSTFIX}_test_hash3_shake)
add_test(NAME ${CMAKE_RELEASE_POSTFIX}_test_ciphers COMMAND ${CMAKE_RELEASE_POSTFIX}_test_ciphers)
add_test(NAME ${CMAKE_RELEASE_POSTFIX}_test_crypto COMMAND ${CMAKE_RELEASE_POSTFIX}_test_crypto)
add_test(NAME ${CMAKE_RELEASE_POSTFIX}_test_keys COMMAND ${CMAKE_RELEASE_POSTFIX}_test_keys)
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
