#!/bin/bash

if [ -x "$(command -v llvm-config-12)"  ]; then
    echo "Find llvm-config-12"
    LLVM_CONFIG="llvm-config-12"
elif [ -x "$(command -v llvm-config)" ]; then
    echo "Find llvm-config"
    LLVM_CONFIG="llvm-config"
else
    echo "Error: No llvm-config found"
    exit 1
fi

export LLVM_DIR=$($LLVM_CONFIG --prefix)
export SVF_DIR="/root/SVF-2.3"
export CC="clang-12"
export CXX="clang++-12"

echo "LLVM_DIR=$LLVM_DIR"
echo "SVF_DIR=$SVF_DIR"

if [ ! -d "$SVF_DIR" ]; then
    echo "Error: SVF directory not found at $SVF_DIR"
    exit 1
fi

rm -rf build
mkdir -p build
cd build

cmake -DCMAKE_BUILD_TYPE=Debug \
      -DLLVM_DIR="$LLVM_DIR" \
      -DSVF_DIR="$SVF_DIR" \
      ..

# cmake -DLLVM_DIR="$LLVM_DIR" \
#       -DSVF_DIR="$SVF_DIR" \
#       ..

make -j$(nproc)

echo "Build completed!"