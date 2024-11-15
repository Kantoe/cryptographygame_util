#include "cryptography_game_util.h"

int main() {
    const char *message = "tlength:38;type:OUT;length:4;data:abcdtlength:40;type:IN;length:7;data:efghijk";
    char data [1024] = {0};
    char type [1024] = {0};
    char length [1024] = {0};

    const int check = parse_received_packets(message, data, type,
            length, strlen(message), sizeof(length),
            sizeof(data), sizeof(type));
    if (check) {
        printf("%s\n%s\n%s\n", data, type, length);
    }
    else {
        printf("bad packet");
    }
    printf("%ld",strlen("tlength:38;type:OUT;length:4;data:abcd"));
    printf("%ld",strlen("tlength:40;type:IN;length:7;data:efghijk"));
    return 0;
}