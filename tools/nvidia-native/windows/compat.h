#pragma once
#include <cstdlib>
#include <ctime>
#include <sys/stat.h>

inline time_t timegm(struct tm* value) { return _mkgmtime(value); }
inline struct tm* gmtime_r(const time_t* value, struct tm* output) {
  return gmtime_s(output, value) == 0 ? output : nullptr;
}
inline int setenv(const char* name, const char* value, int overwrite) {
  if (!overwrite && std::getenv(name)) return 0;
  return _putenv_s(name, value);
}
#ifndef S_ISDIR
#define S_ISDIR(mode) (((mode) & _S_IFMT) == _S_IFDIR)
#endif
