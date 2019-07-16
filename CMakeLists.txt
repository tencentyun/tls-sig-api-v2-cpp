cmake_minimum_required(VERSION 2.8)
project(tls_sig_api)

if(UNIX)
    find_package(ZLIB REQUIRED)
    find_package(OpenSSL REQUIRED)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    # 类 unix 系统使用 openssl 进行加解密
    add_definitions(-DUSE_OPENSSL)
endif()

if(MSVC)

    option(BUILD_STATIC_VCRUNTIME "static link vc runtime" OFF)

    set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /D_SILENCE_TR1_NAMESPACE_DEPRECATION_WARNING /D_CRT_SECURE_NO_WARNINGS")
    add_definitions(/wd"4819")
    foreach(CompilerFlag ${CompilerFlags})
        if (BUILD_STATIC_VCRUNTIME)
            string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
        else()
            string(REPLACE "/MT" "/MD" ${CompilerFlag} "${${CompilerFlag}}")
        endif()
    endforeach()
endif()

add_definitions(-DFMT_HEADER_ONLY -DRAPIDJSON_HAS_STDSTRING=1)

if(UNIX)
    include_directories(
        third/rapidjson/include
        third/fmt/include
        ${ZLIB_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        src
        )

    option(BUILD_SHARED "build tlsignature shared library" OFF)
    if(BUILD_SHARED)
        add_library(tlssigapi_v2 SHARED src/tls_sig_api_v2.cpp src/opensslthreadlock.cpp)
    else()
        add_library(tlssigapi_v2 src/tls_sig_api_v2.cpp src/opensslthreadlock.cpp)
    endif()

    target_link_libraries(tlssigapi_v2
        -lz
        ${OPENSSL_CRYPTO_LIBRARIES}
        )
    
    add_executable(tlssigapi_v2_tool src/tlssigapi_v2_tool.cpp)
    target_link_libraries(tlssigapi_v2_tool
        tlssigapi_v2
        -lz
        ${OPENSSL_CRYPTO_LIBRARIES}
        )
endif()

if(MSVC)
    include_directories(
        third/rapidjson/include
        third/fmt/include
        third/mbedtls/include
        # Windows 上 zlib include 路径需要手动指定
        third/zlib-1.2.11
        src
        )

    option(BUILD_SHARED "build tlsignature shared library" OFF)
    if(BUILD_SHARED)
        add_library(tlssigapi_v2 SHARED src/tls_sig_api_v2.cpp)
    else()
        add_library(tlssigapi_v2 src/tls_sig_api_v2.cpp)
    endif()
    
    if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        set(ZLIB_NAME "third/zlib-1.2.11/Debug/zlibstaticd")
        set(MBEDTLS_NAME "third/mbedtls/crypto/library/Debug/mbedcrypto")
    endif()
    if(${CMAKE_BUILD_TYPE} STREQUAL "Release")
        set(ZLIB_NAME "third/zlib-1.2.11/Release/zlibstatic")
        set(MBEDTLS_NAME "third/mbedtls/crypto/library/Release/mbedcrypto")
    endif()

    target_link_libraries(tlssigapi_v2
        ${ZLIB_NAME}
        ${MBEDTLS_NAME}
        )
    
    add_executable(tlssigapi_v2_tool src/tlssigapi_v2_tool.cpp)
    target_link_libraries(tlssigapi_v2_tool
        tlssigapi_v2
        ${ZLIB_NAME}
        ${MBEDTLS_NAME}
        )
    
endif()

option(BUILD_TEST "build testcase" OFF)
if(BUILD_TEST)
    enable_testing()
    find_package(GTest REQUIRED)
    include_directories(${PROJECT_SOURCE_DIR}/src)
    add_executable(unit_tests test/unit_test.cpp)
    target_link_libraries(unit_tests PRIVATE GTest::GTest GTest::Main 
    ZLIB::ZLIB
    OpenSSL::Crypto)
    add_test(unit_tests unit_tests)
endif()

install(TARGETS tlssigapi_v2
	PERMISSIONS WORLD_READ OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE
	DESTINATION lib)
install(TARGETS tlssigapi_v2_tool
	PERMISSIONS WORLD_READ WORLD_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_WRITE GROUP_EXECUTE
	DESTINATION bin)
install(FILES src/tls_sig_api_v2.h
	PERMISSIONS WORLD_READ OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE
	DESTINATION include)

