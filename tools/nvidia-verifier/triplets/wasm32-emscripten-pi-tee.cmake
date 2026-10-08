# The community Emscripten triplet with source paths removed from objects.
include("${VCPKG_ROOT_DIR}/triplets/community/wasm32-emscripten.cmake")
set(VCPKG_C_FLAGS "-ffile-prefix-map=${VCPKG_ROOT_DIR}=/vcpkg -ffile-prefix-map=$ENV{EMSDK}=/emsdk")
set(VCPKG_CXX_FLAGS "${VCPKG_C_FLAGS}")
set(VCPKG_BUILD_TYPE release)
# libxml2 embeds its catalog path; an absolute /etc keeps it independent of the build root.
if(PORT STREQUAL "libxml2")
  list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS "-DCMAKE_INSTALL_SYSCONFDIR=/etc")
endif()
