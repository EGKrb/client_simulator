cmake_minimum_required(VERSION 3.24)
project(local_test_gateway CXX)
set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

include(FetchContent)
set(LUAU_BUILD_CLI OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(luau GIT_REPOSITORY https://github.com/luau-lang/luau.git GIT_TAG 0.638)
FetchContent_MakeAvailable(luau)

add_executable(ltg main.cpp pki.cpp gateway.cpp rules.cpp mock_controller.cpp)
target_link_libraries(ltg PRIVATE OpenSSL::SSL OpenSSL::Crypto Luau.VM Luau.Compiler ws2_32 crypt32)