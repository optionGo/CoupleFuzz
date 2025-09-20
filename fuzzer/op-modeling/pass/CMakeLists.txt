cmake_minimum_required(VERSION 3.4.3)
project(Loop-Handling-Pass)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(LT_LLVM_INSTALL_DIR "" CACHE PATH "LLVM installation directory")


# if(DEFINED ENV{SVF_DIR})
#     set(SVF_DIR "$ENV{SVF_DIR}" CACHE PATH "SVF installation directory")
# else()
#     set(SVF_DIR "" CACHE PATH "SVF installation directory")
# endif()

list(APPEND CMAKE_PREFIX_PATH "${LT_LLVM_INSTALL_DIR}/lib/cmake/llvm/")

# 10.0.0 is the minimum version for LLVM 10.0.0

find_package(LLVM 10.0.0 REQUIRED CONFIG)
include_directories(../../ ../include)


if (LLVM_FOUND)
    message(STATUS "LLVM_VERSION_MAJOR: ${LLVM_VERSION_MAJOR}")
    message(STATUS "LLVM_VERSION_MINOR: ${LLVM_VERSION_MINOR}")
    message(STATUS "LLVM_VERSION_PATCH: ${LLVM_VERSION_PATCH}")
    if (${LLVM_VERSION_MAJOR} LESS 10)
        message(FATAL_ERROR "LLVM version should be 10.0.0+ !")
    endif()
else()
    message(FATAL_ERROR "You haven't install LLVM !")
endif()


# if(NOT SVF_DIR)
#     message(FATAL_ERROR "SVF_DIR is not set. Please set it to your SVF installation directory.")
# endif()

# set(SVF_LIB "${SVF_DIR}/Release-build/lib/libSvf.a")
# set(LLVMCudd "${SVF_DIR}/Release-build/lib/CUDD/libCudd.a")


# include_directories("${SVF_DIR}/include")
# include_directories("${SVF_DIR}/Release-build/include")

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 14 CACHE STRING "")

if(NOT LLVM_ENABLE_RTTI)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

# add_library(LoopHandlingPass MODULE LoopHandlingPass.cpp)
# install (TARGETS LoopHandlingPass DESTINATION ${ANGORA_PASS_DIR})

add_library(OptionHandlingPass MODULE OptionHandlingPass.cpp ../../cJSON.c)
install (TARGETS OptionHandlingPass DESTINATION ${ANGORA_PASS_DIR})


# add_library(cbi MODULE cbi.cpp)
# target_link_libraries(cbi ${SVF_LIB} ${LLVMCudd})
# install (TARGETS cbi DESTINATION ${ANGORA_PASS_DIR})

add_library(DFSanPass MODULE DataFlowSanitizer.cpp)
# target_link_libraries(DFSanPass LLVMPassConfig)
install (TARGETS DFSanPass DESTINATION ${ANGORA_PASS_DIR})
