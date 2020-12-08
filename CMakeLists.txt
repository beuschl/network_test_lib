cmake_minimum_required(VERSION 3.4.3)

project(network_test_lib
    LANGUAGES CXX C
)

# Use plain -std=c++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

####################################################################################################
# CMake modules


####################################################################################################
# definitions and configuration

set(CMAKE_POSITION_INDEPENDENT_CODE ON CACHE BOOL
    "Enable position-independent code for STATIC libraries.")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(UNIX)
    add_definitions(-DUNIX)
endif()

if(WIN32)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

    add_definitions(
        # minimum supported Windows API
        -D_WIN32_WINNT=0x0501
        # required for using std::numeric_limits<T>::max|min,
        # otherwise windows.h will preprocess 'max'
        -DNOMINMAX
        # turn off unnecessary warnings
        -D_SILENCE_TR1_NAMESPACE_DEPRECATION_WARNING
        -D_CRT_SECURE_NO_WARNINGS
    )
endif()

if(MSVC)
    # enable multi threaded build
    add_definitions(/MP)
    # enable C++ standard conformance
    add_definitions(/permissive-)
endif()

####################################################################################################
# package inclusions

# settings for asio library
set(ASIO_COMPILE_DEFINITIONS
    ASIO_STANDALONE ASIO_HEADER_ONLY ASIO_SEPARATE_COMPILATION ASIO_NO_TYPEID
)
if(WIN32)
    list(APPEND ASIO_COMPILE_DEFINITIONS ASIO_WINDOWS _WIN32_WINNT=0x0501 __USE_W32_SOCKETS)
endif()

# external libraries
find_package(Threads REQUIRED)

####################################################################################################
# subdirectories

add_subdirectory(include)
