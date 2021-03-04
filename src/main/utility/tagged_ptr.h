#include <stdint.h>

extern const TAG_MASK;

uintptr_t tagPtr(void* ptr, uintptr_t tag);
void* untagPtr(uintptr_t taggedPtr, uintptr_t* tag);
