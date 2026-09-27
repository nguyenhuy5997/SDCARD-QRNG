#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
void __ubsan_handle_shift_out_of_bounds_abort(void *data, uintptr_t lhs, uintptr_t rhs) {
 (void)data; printf("UBSan_shift_error lhs=%llu rhs=%llu\n",(unsigned long long)lhs,(unsigned long long)rhs);exit(77);
}
