cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(modoru)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(VITA_APP_NAME "modoru 戻る")
set(VITA_TITLEID  "MODORU000")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

link_directories(
  ${CMAKE_BINARY_DIR}/modoru_kernel_stubs
)

add_executable(modoru
  main.c
  scr_printf.c
  font.c
)

add_dependencies(modoru tiny_modoru.skprx)

target_link_libraries(modoru
  SceAppMgr_stub
  SceCtrl_stub
  SceDisplay_stub
  ScePower_stub
  SceVshBridge_stub
  taihen_stub
  modoru_kernel_stub
)

vita_create_self(tny_modoru.self modoru UNSAFE)

add_executable(modoru_kernel
  kernel.c
)
set_target_properties(modoru_kernel
  PROPERTIES LINK_FLAGS
  -nostdlib
)
target_link_libraries(modoru_kernel
  SceAppMgrForDriver_stub
  SceCtrlForDriver_stub
  SceCpuForDriver_stub
  SceKernelUtilsForDriver_stub
  SceModulemgrForDriver_stub
  SceSblSsMgrForDriver_stub
  SceSysclibForDriver_stub
  SceSysmemForDriver_stub
  SceSysrootForKernel_stub
  SceThreadmgrForDriver_stub
  taihenForKernel_stub
  taihenModuleUtils_stub
  SceSdifForDriver_stub
  SceDebugForDriver_stub
)
vita_create_self(tiny_modoru.skprx modoru_kernel
  CONFIG ${CMAKE_SOURCE_DIR}/kernel_exports.yml
  UNSAFE
)
vita_create_stubs(modoru_kernel_stubs modoru_kernel ${CMAKE_SOURCE_DIR}/kernel_exports.yml KERNEL)

add_executable(modoru_user
  user.c
)
set_target_properties(modoru_user
  PROPERTIES LINK_FLAGS
  -nostartfiles
)
target_link_libraries(modoru_user
  SceAppMgr_stub
  SceShellSvc_stub
  ScePower_stub
  taihen_stub
)
vita_create_self(tiny_modoru.suprx modoru_user
  CONFIG ${CMAKE_SOURCE_DIR}/user_exports.yml
  UNSAFE
)

add_dependencies(modoru_user modoru_kernel_stubs)
add_dependencies(modoru tiny_modoru.skprx)
add_dependencies(modoru tiny_modoru.suprx)
