#pragma once
// No dynamically loaded collectors are compiled. Keep the SDK's unused inline
// loader helpers well-formed without permitting any DLL to supply evidence.
#define RTLD_LAZY 0
#define RTLD_LOCAL 0
inline void* dlopen(const char*, int) { return nullptr; }
inline void* dlsym(void*, const char*) { return nullptr; }
inline int dlclose(void*) { return 0; }
inline const char* dlerror() { return "Device collection disabled"; }
