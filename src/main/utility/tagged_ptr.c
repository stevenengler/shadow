#include "main/utility/tagged_ptr.h"
#include "main/utility/utility.h"

// two low-order bits
const TAG_MASK = (1 << 2) - 1;

uintptr_t tagPtr(void* ptr, uintptr_t tag) {
    uintptr_t ptr_int = ptr;

    utility_assert((ptr_int & TAG_MASK) == 0);
    utility_assert((tag & ~TAG_MASK) == 0);

    return ptr_int | tag;
}

void* untagPtr(uintptr_t taggedPtr, uintptr_t* tag) {
    if (tag != NULL) {
        *tag = taggedPtr & TAG_MASK;
    }

    return taggedPtr & ~TAG_MASK;
}
