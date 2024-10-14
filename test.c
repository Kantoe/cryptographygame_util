#include "cryptography_game_util.h"

int main() {

    const int socket = createTCPIpv4Socket();
    struct sockaddr_in address;
    createIPv4Address("127.0.0.1", 2000, &address);
    connect(socket, (struct sockaddr *)&address,sizeof(address));
    execute_command_and_send("cat /home/idokantor/test.txt", socket);
    close(socket);
    return 0;
}