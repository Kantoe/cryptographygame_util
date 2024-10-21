#include <signal.h>
#include <stdatomic.h>

#include "cryptography_game_util.h"
int main() {
    const char *message = "tlength:38;type:OUT;length:4;data:abcdtlength:40;type:IN;length:7;data:efghijk";
    char data [1024] = {0};
    const int check = parse_received_packets(message, data, strlen(message));
    if (check) {
        printf("%s\n", data);
    }
    else {
        printf("bad packet");
    }
    return 0;
}