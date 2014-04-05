cmake_minimum_required(VERSION 2.8)

project(udp_test)

include(Triplet.cmake)

set(bd ${CMAKE_CURRENT_LIST_DIR})

include_directories(
  ${extern_include_dir}
  ${install_dir}/include/
)

add_definitions(-DENABLE_DEBUGGING)

#add_executable(udp_server 
#  ${bd}/../src/udp_server.c
#  ${bd}/../src/krx_dtls.c
#  ${bd}/../src/krx_rtp.c
#  ${bd}/../src/krx_ivf.c
#)

#add_executable(udp_client ${bd}/../src/udp_client.cpp)
#add_executable(ssl_test ${bd}/../src/ssl_test.c)
#add_executable(ssl_test2 ${bd}/../src/ssl_test2.c)

add_executable(sdp_parser_test ${bd}/../src/sdp_parser_test.c)

add_executable(signal_server 
  ${bd}/../src/signal_server.c
  ${bd}/../src/krx_https.c
  ${bd}/../src/krx_signaling.c
  ${extern_source_dir}/http_parser.c
)

set(libraries
  ${extern_lib_dir}/libssl.a
  ${extern_lib_dir}/libcrypto.a
  ${extern_lib_dir}/libsrtp.a
  ${extern_lib_dir}/libuv.a
  ${extern_lib_dir}/libsofia-sip-ua.a
  ${extern_lib_dir}/libjansson.a
  ${install_dir}/lib/libstun.a
)

if(APPLE)
  find_library(fr_corefoundation CoreFoundation)
  find_library(fr_cocoa Cocoa)
  find_library(fr_iokit IOKit)
 
  list(APPEND libraries
    ${fr_corefoundation}
    ${fr_cocoa}
    ${fr_iokit}  
    )

endif()

#target_link_libraries(udp_client ${libraries})
#target_link_libraries(udp_server ${libraries})
#target_link_libraries(ssl_test ${libraries})
#target_link_libraries(ssl_test2 ${libraries})

target_link_libraries(signal_server ${libraries})
target_link_libraries(sdp_parser_test ${libraries})
 
set(CMAKE_INSTALL_PREFIX ${install_dir})

install(TARGETS signal_server DESTINATION bin)
install(TARGETS sdp_parser_test DESTINATION bin)

#install(TARGETS udp_server DESTINATION bin)
#install(TARGETS udp_client DESTINATION bin)
#install(TARGETS ssl_test DESTINATION bin)
#install(TARGETS ssl_test2 DESTINATION bin)

