cmake_minimum_required(VERSION 3.20)

project(AntiMinerCMake LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(anti-miner WIN32
    src/main.cpp
)

target_compile_definitions(anti-miner PRIVATE
    UNICODE
    _UNICODE
)

# Optional: pass VirusTotal API key at build time:
#   cmake -S . -B build -DVT_API_KEY="your_key"
if(DEFINED VT_API_KEY)
    target_compile_definitions(anti-miner PRIVATE VT_API_KEY="${VT_API_KEY}")
endif()

target_link_libraries(anti-miner PRIVATE
    advapi32
    bcrypt
    ole32
    oleaut32
    wbemuuid
    winhttp
)


