#!/bin/sh

if [ ! -d build.release ] ; then
    mkdir build.release 
fi

cd build.release
cmake -DCMAKE_BUILD_TYPE=Release ../
cmake --build . --target install

if [ "$(uname)" == "Darwin" ] ; then 
    cd ./../../../../install/mac-clang-x86_64/bin/
    #./test_pjsip_sdp
    ./test_ice
    #./ice_test
    #./stun_test
    #./signal_server
    #./sdp_parser_test
    #./udp_server
    #./ssl_test
    #./ssl_test2
else
    cd ./../../../../install/linux-gcc-x86_64/bin/
    ./udp_server
fi
