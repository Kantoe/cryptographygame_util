/*
* Ido Kantor
* methods used in code for the game
 */
#include "cryptography_game_util.h"


int createTCPIpv4Socket()
{
    return socket(AF_INET, SOCK_STREAM, SOCKET_FLAG);
}


int createIPv4Address(const char *ip, const int port, struct sockaddr_in *address)
{
    int ip_check = 1;
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    if(strlen(ip) == NO_IP) {
        address->sin_addr.s_addr = INADDR_ANY;
    }
    else {
        ip_check = inet_pton(AF_INET,ip , &address->sin_addr.s_addr);
    }
    return PORT_RANGE_MIN < port && port <= PORT_RANGE_MAX && ip_check != CHECK_IP;
}

int execute_command_and_send(const char* command, const int socket_fd) {
    FILE* fp = popen(command, "r");  // Open the command for reading
    if(fp == NULL) {
        perror("popen failed");
        return -1;
    }
    char output[256];
    // Read each line from the command output
    while (fgets(output, sizeof(output), fp) != NULL) {
        char buffer[260];
        snprintf(buffer, sizeof(buffer), "OUT %s", output);
        send(socket_fd, buffer, strlen(buffer), 0);
    }
    pclose(fp);  // Close the file pointer
    return 0;
}
