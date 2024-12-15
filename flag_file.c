#include "flag_file.h"

__uint32_t gen_random_number(const unsigned int max_value) {
    return arc4random_uniform(max_value);
}
