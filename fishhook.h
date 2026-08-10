#ifndef fishhook_h
#define fishhook_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Cấu trúc mô tả một symbol cần rebind (hook)
 */
struct rebinding {
  const char *name;
  void *replacement;
  void **replaced;
};

/*
 * Hàm rebind_symbols nhận vào mảng các struct rebinding
 */
int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);

#ifdef __cplusplus
}
#endif

#endif /* fishhook_h */
