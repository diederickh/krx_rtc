#!/bin/sh

if [ ! -d build.release ] ; then 
    mkdir build.release
fi

cd build.release
cmake ../
cmake --build . --target install
