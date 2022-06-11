cmake_minimum_required(VERSION 3.22)
project(_Graduate_Design_Management_System)
find_package(Qt5 COMPONENTS Widgets Core Sql REQUIRED)
find_package(CapnProto CONFIG REQUIRED)
find_package(QuaZip-Qt5)
find_path(HIREDIS_HEADER hiredis)
find_library(HIREDIS_LIB hiredis)
find_path(REDIS_PLUS_PLUS_HEADER sw)
find_library(REDIS_PLUS_PLUS_LIB redis++)
include(FetchContent)
FetchContent_Declare(SHA256
        GIT_REPOSITORY https://github.com/System-Glitch/SHA256.git)
FetchContent_MakeAvailable(SHA256)
FetchContent_Declare(Qt-Secret
        GIT_REPOSITORY https://github.com/QuasarApp/Qt-Secret.git
        GIT_TAG main
        )
FetchContent_MakeAvailable(Qt-Secret)

set(CMAKE_CXX_STANDARD 20)
capnp_generate_cpp(accountSrc accountHeader schema/account.capnp)
capnp_generate_cpp(systemSrc systemHeader schema/system.capnp)

add_executable(_Graduate_Design_Management_System main.cpp ${systemSrc} ${accountSrc})
target_include_directories(_Graduate_Design_Management_System PUBLIC ${HIREDIS_HEADER} ${REDIS_PLUS_PLUS_HEADER})
target_link_libraries(_Graduate_Design_Management_System PUBLIC ${CAPNP_LIBRARIES} sha256 ${HIREDIS_LIB} ${REDIS_PLUS_PLUS_LIB} Qt-Secret QuaZip::QuaZip Qt5::Core Qt5::Sql)
target_include_directories(_Graduate_Design_Management_System PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/schema ${sha256_SOURCE_DIR})

add_executable(testClient testClient.cpp ${systemSrc} ${accountSrc})
target_link_libraries(testClient PUBLIC ${CAPNP_LIBRARIES} sha256 Qt-Secret QuaZip::QuaZip)
target_include_directories(testClient PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/schema ${sha256_SOURCE_DIR})

