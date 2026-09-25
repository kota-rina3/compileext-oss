cmake_minimum_required(VERSION 3.15)
project(compileext_oss CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(MODULE_NAME "CompileExt" CACHE STRING "Node 模块名（必须叫 CompileExt 才能被 dist/CompileUtil.js 加载）")

# ---------- 获取 N-API 头文件 ----------
# 优先级：NODE_HEADERS_DIR 变量 > 系统路径自动查找 > 自动下载 nodejs.org 官方头文件包
set(NODE_HEADERS_DIR "" CACHE PATH "node 头文件目录（含 node_api.h）")

if(NOT NODE_HEADERS_DIR)
    find_path(_FOUND_NODE_HEADERS node_api.h
        PATHS
            /usr/include/node
            /usr/local/include/node
            /opt/homebrew/include/node
        NO_DEFAULT_PATH)
    if(_FOUND_NODE_HEADERS)
        set(NODE_HEADERS_DIR ${_FOUND_NODE_HEADERS})
        message(STATUS "使用系统 node 头文件: ${NODE_HEADERS_DIR}")
    else()
        set(NODE_VERSION "22.21.1" CACHE STRING "自动下载的 node 版本")
        set(_URL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-headers.tar.gz")
        set(_TAR "${CMAKE_BINARY_DIR}/node-headers.tar.gz")
        set(_DIR "${CMAKE_BINARY_DIR}/node-headers")
        if(NOT EXISTS "${_DIR}/include/node/node_api.h")
            if(NOT EXISTS "${_TAR}")
                message(STATUS "下载 node 头文件: ${_URL}")
                file(DOWNLOAD "${_URL}" "${_TAR}" SHOW_PROGRESS STATUS _st)
                list(GET _st 0 _code)
                if(NOT _code EQUAL 0)
                    message(FATAL_ERROR "下载 node 头文件失败（离线环境请用 -DNODE_HEADERS_DIR= 指定本地目录）")
                endif()
            endif()
            file(ARCHIVE_EXTRACT INPUT "${_TAR}" DESTINATION "${_DIR}")
        endif()
        set(NODE_HEADERS_DIR "${_DIR}/include/node")
        message(STATUS "使用下载的 node 头文件: ${NODE_HEADERS_DIR}")
    endif()
endif()

# ---------- 目标 ----------
add_library(${MODULE_NAME} SHARED src/compileext.cpp)
target_include_directories(${MODULE_NAME} PRIVATE ${NODE_HEADERS_DIR} src)
target_compile_definitions(${MODULE_NAME} PRIVATE NODE_GYP_MODULE_NAME=${MODULE_NAME})

set_target_properties(${MODULE_NAME} PROPERTIES
    PREFIX ""            # 不要 lib 前缀
    SUFFIX ".node")      # node 扩展后缀

if(APPLE)
    target_link_options(${MODULE_NAME} PRIVATE "-undefined" "dynamic_lookup")
elseif(MSVC)
    target_compile_options(${MODULE_NAME} PRIVATE /EHsc /Zc:__cplusplus)
else()
    # Linux: 不链接 libnode，符号运行时由宿主（Node/Electron）提供
    target_link_options(${MODULE_NAME} PRIVATE "-Wl,--allow-shlib-undefined")
endif()
