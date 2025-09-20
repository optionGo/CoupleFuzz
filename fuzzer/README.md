# Option Fuzz
## Usage
### compile fuzzer
```shell
# in ubuntu: 20.04
sudo apt-get install clang-12 lld-12
apt-get install -y xz-utils cmake ninja-build gcc g++ python3 doxygen python3-distutils
apt install -y libc6-dev-i386 gcc-multilib g++-multilib
apt install clang-10 libc++-10-dev libc++abi-10-dev
apt install libpcre3 libpcre3-dev -y
git clone https://github.com/SRI-CSL/gllvm.git
cd gllvm
git checkout v1.3.0
go install ./cmd/...
# compile fuzzer
# Environment variables
export CC=clang-12
export CXX=clang++-12
export LLVM_CONFIG=llvm-config-12
export AFL_REAL_LD=ld.lld-12
cd optionfuzz && make 
cd instrument && bash ./build.sh
cd op-modeling && bash ./build.sh
```

### example
```shell
# step1: calculate distance and instrument
export LLVM_CONFIG=llvm-config-12
export AFL_REAL_LD=ld.lld-12
export CC="/home/optionfuzz/afl-clang-fast"
export CXX="/home/optionfuzz/afl-clang-fast++"
export AS="$(which llvm-as-12)"
export RANLIB="$(which llvm-ranlib-12)"
export AR="$(which llvm-ar-12)"
export LD="$(which ld.lld-12)"
export NM="$(which llvm-nm-12)"
export AFL_CC=clang-12
export AFL_CXX=clang++-12
export WR_BB_TARGETS="/home/test/libtiff-src/BBtargets.txt"
export WR_TARGETS="tiffcrop" # or "::" for all programs
unset CFLAGS
unset CXXFLAGS
./configure --prefix=$PWD/build_afl --disable-shared
make -j && make install

# step2: dynamic taint analysis
export CXX10="/usr/bin/clang++-10"
export CC10="/usr/bin/clang-10"
export CC="/home/optionfuzz/op-modeling/install/test-clang"
export CXX="/home/optionfuzz/op-modeling/install/test-clang++"
export CFLAGS="-parameter-option-path /home/test/libtiff-src/option_all.json -distance-path /home/distance.txt"
export CXXFLAGS=$CFLAGS
./configure --prefix=$PWD/build_taint --disable-shared
make -j > make_output.txt 2>&1 && make install

export RUST_BACKTRACE=1
nohup ./build_taint/bin/tiffcrop -E right -U in -z 1,1,2048,2048:1,2049,2048,4097 -i ./test/images/deflate-last-strip-extra-data.tiff.isi /tmp/foo > tiffcrop_output.txt 2>&1 &
```

# new

```shell
export PATH=/usr/lib/llvm-10/bin:$PATH
export PATH=/usr/lib/llvm-10/lib:$PATH
export PATH=/root/go/bin:$PATH

export CC="gclang"
export CXX="gclang++"
export CFLAGS="-g -fno-omit-frame-pointer -Wno-error"
export export CXXFLAGS="$CFLAGS"
export LDFLAGS="-lpthread -flto -Wl,-plugin-opt=save-temps"
get-bc $BIN_NAME

cbi --targets=/path/to/BBtargts.txt $BIN_NAME.bc
/home/optionfuzz/afl-clang-fast ./$BIN_NAME.ci.bc "dynamic link lib" -fsanitize=address -o $BIN_NAME_O
```

# calcalate distance
```bash
export AFL_FAST_CAL=1
/home/optionfuzz/afl-dryrun -m none -z exp -c 45m -i /home/evaluation/tiffcrop-2023-25433/libtiff/fuzz_build/bin/out/queue -o dryrun_out ./tiffcrop-2023-25433 %% @@ /dev/null
```