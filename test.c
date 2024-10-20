#include "cryptography_game_util.h"
int main() {
    const char *message = "tlength:38;type:OUT;length:4;data:abcdtlength:39;type:IN;length:6;data:efghij";
    char data [1024] = {0};
    const int check = parse_received_packets(message, data, strlen(message));
    printf("%ld\n", strlen("tlength:20;type:OUT;length:4;data:abcd"));
    printf("%ld\n", strlen("tlength:22;type:IN;length:6;data:efghij"));
    if (check != -1) {
        printf("%s\n", data);
    }
    else {
        printf("bad packet\n");
    }
    return 0;
}