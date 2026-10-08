cmake_minimum_required(VERSION 3.25)
project(pi-tee-nvidia-native VERSION 1.2.2 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
if(NOT DEFINED NVIDIA_SOURCE OR NOT DEFINED PATCHED_SOURCE OR NOT DEFINED REGORUS_SOURCE OR NOT DEFINED REGORUS_LIBRARY)
  message(FATAL_ERROR "Use the locked maintainer build script")
endif()
set(sdk "${NVIDIA_SOURCE}/nv-attestation-sdk-cpp")
set(cli "${NVIDIA_SOURCE}/nv-attestation-cli")
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(unofficial-xmlsec CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)
find_package(CLI11 CONFIG REQUIRED)
find_package(Threads REQUIRED)
configure_file("${sdk}/include/nvat.h.in" "include/nvat.h")

# Preserve every verification source except hash-locked patches in source-lock.json.
# The three collector implementations are replaced; they always reject instead
# of loading hardware libraries.
add_library(nvat STATIC
  ${sdk}/src/nvat.cpp ${sdk}/src/attestation.cpp ${sdk}/src/claims.cpp ${sdk}/src/claims_evaluator.cpp
  ${sdk}/src/gpu/evidence.cpp ${sdk}/src/gpu/claims.cpp ${sdk}/src/gpu/verify.cpp
  ${sdk}/src/spdm/spdm_measurement_records.cpp ${sdk}/src/spdm/spdm_opaque_data_parser.cpp
  ${sdk}/src/gpu/spdm/gpu_opaque_data_parser.cpp ${sdk}/src/spdm/spdm_req.cpp ${sdk}/src/spdm/spdm_resp.cpp
  ${sdk}/src/init.cpp ${sdk}/src/log.cpp ${sdk}/src/nv_x509.cpp ${sdk}/src/rego_engine/regorus_rego_engine.cpp
  ${PATCHED_SOURCE}/nv-attestation-sdk-cpp/src/rim.cpp ${sdk}/src/switch/evidence.cpp ${sdk}/src/switch/claims.cpp ${sdk}/src/switch/verify.cpp
  ${sdk}/src/verify.cpp ${sdk}/src/switch/spdm/switch_opaque_data_parser.cpp ${sdk}/src/nv_http.cpp
  ${sdk}/src/nv_jwt.cpp ${sdk}/src/nv_ocsp.cpp ${sdk}/src/utils.cpp ${sdk}/src/nv_cache.cpp
  collectors-disabled.cpp)
target_include_directories(nvat PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/include"
  PRIVATE "${sdk}/src" "${sdk}/include" "${REGORUS_SOURCE}/bindings/ffi")
target_compile_definitions(nvat PRIVATE JWT_DISABLE_PICOJSON)
target_link_libraries(nvat PUBLIC unofficial::xmlsec::xmlsec1 unofficial::xmlsec::xmlsec1-openssl
  OpenSSL::SSL OpenSSL::Crypto CURL::libcurl LibXml2::LibXml2 spdlog::spdlog fmt::fmt
  jwt-cpp::jwt-cpp nlohmann_json::nlohmann_json "${REGORUS_LIBRARY}" Threads::Threads ${CMAKE_DL_LIBS})
if(APPLE)
  target_link_libraries(nvat PUBLIC "-framework CoreFoundation" "-framework Security" iconv resolv)
elseif(WIN32)
  target_link_libraries(nvat PUBLIC ws2_32 userenv bcrypt ntdll advapi32)
endif()

set(NVATTEST_FULL_VERSION "1.2.2+pi-tee-candidate")
configure_file("${cli}/src/version_config.h.in" "version_config.h")
add_executable(nvattest ${cli}/src/main.cpp ${cli}/src/version.cpp ${cli}/src/attest.cpp
  ${cli}/src/collect_evidence.cpp ${cli}/src/utils.cpp ${cli}/src/logging.cpp)
target_include_directories(nvattest PRIVATE "${cli}/src" "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(nvattest PRIVATE nvat CLI11::CLI11)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  foreach(target nvat nvattest)
    target_compile_options(${target} PRIVATE "-ffile-prefix-map=${NVIDIA_SOURCE}=/nvidia-sdk" "-ffile-prefix-map=${PATCHED_SOURCE}=/nvidia-sdk"
      "-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=/pi-tee-nvidia-recipe")
  endforeach()
endif()
if(MSVC)
  foreach(target nvat nvattest)
    target_compile_definitions(${target} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_include_directories(${target} PRIVATE windows)
    target_compile_options(${target} PRIVATE "/FI${CMAKE_CURRENT_SOURCE_DIR}/windows/compat.h"
      "/pathmap:${NVIDIA_SOURCE}=/nvidia-sdk" "/pathmap:${PATCHED_SOURCE}=/nvidia-sdk" "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}=/pi-tee-nvidia-recipe")
  endforeach()
endif()
install(TARGETS nvattest RUNTIME DESTINATION bin)
