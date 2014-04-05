#!/bin/sh

if [ ! -d build.release ] ; then
    mkdir build.release 
fi

cd build.release
cmake ../
cmake --build . --target install

if [ "$(uname)" == "Darwin" ] ; then 
    cd ./../../../../install/mac-clang-x86_64/bin/
    ./signal_server
    #./sdp_parser_test
    #./udp_server
    #./ssl_test
    #./ssl_test2
else
    cd ./../../../../install/linux-gcc-x86_64/bin/
    ./udp_server
fi
