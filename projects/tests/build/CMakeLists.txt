cmake_minimum_required(VERSION 2.8)

project(udp_test)

include(Triplet.cmake)

set(bd ${CMAKE_CURRENT_LIST_DIR})

set(use_test_stun FALSE)
set(use_test_ice TRUE)

include_directories(
  ${extern_include_dir}
  ${install_dir}/include/
)

add_definitions(-DENABLE_DEBUGGING)

set(libraries
  ${extern_lib_dir}/libssl.a
  ${extern_lib_dir}/libcrypto.a
  ${extern_lib_dir}/libsrtp.a
  ${extern_lib_dir}/libuv.a
  ${extern_lib_dir}/libsofia-sip-ua.a
  ${extern_lib_dir}/libjansson.a
  ${extern_lib_dir}/libpjnath.a
  ${extern_lib_dir}/libpj.a
  ${extern_lib_dir}/libpjlib-util.a
  ${extern_lib_dir}/libpjmedia.a
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

set(CMAKE_INSTALL_PREFIX ${install_dir})

if(use_test_stun)

  set(test_stun "test_stun")
  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(test_stun "test_stun_debug")
  endif()

  add_executable(${test_stun}
    ${bd}/../src/test_stun.c
    ${bd}/../src/krx_stun.c
    ${bd}/../src/krx_utils.c
    ${bd}/../src/krx_memory.c
    ${bd}/../src/krx_sdp.c
    )
  target_link_libraries(${test_stun} ${libraries})
  install(TARGETS ${test_stun} DESTINATION bin)
endif()


if(use_test_ice)

  set(app "test_ice")
  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(app "test_ice_debug")
  endif()

  add_executable(${app}
    ${bd}/../src/test_krx_ice.c
    ${bd}/../src/krx_stun.c
    ${bd}/../src/krx_utils.c
    ${bd}/../src/krx_memory.c
    ${bd}/../src/krx_sdp.c
    ${bd}/../src/krx_ice.c
    )
  target_link_libraries(${app} ${libraries})
  install(TARGETS ${app} DESTINATION bin)
endif()


# -----------------------------------------------------------------------------------------

# set(use_sdp_parser FALSE)
# set(use_signal_server FALSE)
# set(use_udp_server FALSE)
# set(use_stun_test FALSE)
# set(use_ice_test TRUE)
# set(use_test_ice TRUE) # custom parser
# set(use_pjsip_sdp_test TRUE)


#if(use_udp_server)
#    add_executable(udp_server 
#      ${bd}/../src/udp_server.c
#      ${bd}/../src/krx_dtls.c
#      ${bd}/../src/krx_rtp.c
#      ${bd}/../src/krx_ivf.c
#      )
#endif()

#add_executable(udp_client ${bd}/../src/udp_client.cpp)
#add_executable(ssl_test ${bd}/../src/ssl_test.c)
#add_executable(ssl_test2 ${bd}/../src/ssl_test2.c)

# if(use_sdp_parser)
#   add_executable(sdp_parser_test ${bd}/../src/sdp_parser_test.c)
# endif()
# 
# if(use_signal_server)
#   add_executable(signal_server 
#     ${bd}/../src/signal_server.c
#     ${bd}/../src/krx_https.c
#     ${bd}/../src/krx_signaling.c
#     ${extern_source_dir}/http_parser.c
#     )
# endif()
# 
# if(use_ice_test) 
#   add_executable(ice_test
#     ${bd}/../src/ice_test.c
#     ${bd}/../src/krx_ice_pjnath.c
#     ${bd}/../src/krx_sdp.c
#     ${bd}/../src/krx_global.c
#     )
# endif()
# 
# if(use_test_ice)
#   add_executable(test_ice
#     ${bd}/../src/test_rx_sdp.c
#     ${bd}/../src/rx_sdp.c
#     )
# endif()
# 
# if(use_stun_test)
#   add_executable(stun_test
#     ${bd}/../src/stun_test.c
#     )
# endif()
# 
# if(use_pjsip_sdp_test) 
#   add_executable(test_pjsip_sdp
#     ${bd}/../src/test_pjsip_sdp.c
#     )
# endif()


#target_link_libraries(udp_client ${libraries})
#target_link_libraries(udp_server ${libraries})
#target_link_libraries(ssl_test ${libraries})
#target_link_libraries(ssl_test2 ${libraries})

# if(use_signal_server)
#   target_link_libraries(signal_server ${libraries})
#   install(TARGETS signal_server DESTINATION bin)
# endif()
# 
# if(use_sdp_parser) 
#   target_link_libraries(sdp_parser_test ${libraries})
#   install(TARGETS sdp_parser_test DESTINATION bin)
# endif()
# 
# if(use_stun_test)
#   target_link_libraries(stun_test ${libraries})
#   install(TARGETS stun_test DESTINATION bin)
# endif()
#  
# if(use_ice_test)
#   target_link_libraries(ice_test ${libraries})
#   install(TARGETS ice_test DESTINATION bin)
# endif()
# 
# # own sdp parser
# if(use_test_ice)
#   target_link_libraries(test_ice ${libraries})
#   install(TARGETS test_ice DESTINATION bin)
# endif()
#  
# if(use_pjsip_sdp_test) 
#   target_link_libraries(test_pjsip_sdp ${libraries})
#   install(TARGETS test_pjsip_sdp DESTINATION bin)
# endif()

#install(TARGETS udp_server DESTINATION bin)
#install(TARGETS udp_client DESTINATION bin)
#install(TARGETS ssl_test DESTINATION bin)
#install(TARGETS ssl_test2 DESTINATION bin)

