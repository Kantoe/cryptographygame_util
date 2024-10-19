#include "cryptography_game_util.h"
int main() {
    parse_output("OUT;2;AB;END;OUT;3;EFG;END;OUT;OUT;5;11111;END;", sizeof("OUT;2;AB;END;OUT;3;EFG;END;OUT;OUT;5;11111;END;"));
}