cmake_minimum_required(VERSION 2.8)

project(udp_test)

include(Triplet.cmake)

set(bd ${CMAKE_CURRENT_LIST_DIR})

include_directories(
  ${extern_include_dir}
  ${install_dir}/include/
)

add_definitions(-DENABLE_DEBUGGING)

add_executable(udp_server 
  ${bd}/../src/udp_server.c
  ${bd}/../src/krx_dtls.c
  ${bd}/../src/krx_rtp.c
  ${bd}/../src/krx_ivf.c
)

add_executable(udp_client ${bd}/../src/udp_client.cpp)
add_executable(ssl_test ${bd}/../src/ssl_test.c)
add_executable(ssl_test2 ${bd}/../src/ssl_test2.c)

set(libraries
  ${extern_lib_dir}/libssl.a
  ${extern_lib_dir}/libcrypto.a
  ${extern_lib_dir}/libsrtp.a
  ${install_dir}/lib/libstun.a
)

target_link_libraries(udp_client ${libraries})
target_link_libraries(udp_server ${libraries})
target_link_libraries(ssl_test ${libraries})
target_link_libraries(ssl_test2 ${libraries})
 
set(CMAKE_INSTALL_PREFIX ${install_dir})

install(TARGETS udp_server DESTINATION bin)
install(TARGETS udp_client DESTINATION bin)
install(TARGETS ssl_test DESTINATION bin)
install(TARGETS ssl_test2 DESTINATION bin)

