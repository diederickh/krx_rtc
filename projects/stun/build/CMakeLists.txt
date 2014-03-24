cmake_minimum_required(VERSION 2.8)

project(stun)

include(Triplet.cmake)

set(bd ${CMAKE_CURRENT_LIST_DIR}/..)

add_definitions(
  -DPACKAGE_STRING="krx_stun"
)

include_directories(
  ${bd}
  ${bd}/../
)

set(stun_sources
  ${bd}/debug.c
  ${bd}/md5.c
  ${bd}/rand.c
  ${bd}/sha1.c
  ${bd}/stun5389.c
  ${bd}/stunagent.c
  ${bd}/stuncrc32.c
  ${bd}/stunhmac.c
  ${bd}/stunmessage.c
  ${bd}/utils.c
  ${bd}/usages/bind.c
  ${bd}/usages/ice.c
  ${bd}/usages/timer.c
  ${bd}/usages/turn.c
  )

set(stun_headers
  ${bd}/constants.h
  ${bd}/debug.h
  ${bd}/md5.h
  ${bd}/rand.h
  ${bd}/sha1.h
  ${bd}/stun5389.h
  ${bd}/stunagent.h
  ${bd}/stuncrc32.h
  ${bd}/stunhmac.h
  ${bd}/stunmessage.h
  ${bd}/utils.h
  ${bd}/win32_common.h
  )

add_library(stun ${stun_sources})

set(CMAKE_INSTALL_PREFIX ${install_dir})

install(TARGETS stun ARCHIVE DESTINATION lib)
install(FILES ${stun_headers} DESTINATION include)