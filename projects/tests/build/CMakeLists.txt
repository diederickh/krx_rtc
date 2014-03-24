cmake_minimum_required(VERSION 2.8)

project(udp_test)

include(Triplet.cmake)

set(bd ${CMAKE_CURRENT_LIST_DIR})

include_directories(
  ${extern_include_dir}
  ${install_dir}/include/
)

add_executable(udp_server ${bd}/../src/udp_server.cpp)
add_executable(udp_client ${bd}/../src/udp_client.cpp)

set(libraries
  ${extern_lib_dir}/libssl.a
  ${extern_lib_dir}/libcrypto.a
  ${install_dir}/lib/libstun.a
)

target_link_libraries(udp_client ${libraries})
 
set(CMAKE_INSTALL_PREFIX ${install_dir})

install(TARGETS udp_server DESTINATION bin)
install(TARGETS udp_client DESTINATION bin)
