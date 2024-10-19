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
    int pfd[2];  // Pipe file descriptors
    if (pipe(pfd) < 0) {
        perror("pipe failed");
        return -1;
    }
    char full_command[512];
    snprintf(full_command, sizeof(full_command), "%s 2>&%d", command, pfd[1]);
    FILE* pout = popen(full_command, "r");
    if (pout == NULL) {
        perror("popen failed");
        close(pfd[1]);
        return -1;
    }
    close(pfd[1]);
    char output[1024];
    while (fgets(output, sizeof(output), pout) != NULL) {
        // Send each line to the socket
        char buffer[1028] = {0}; // +4 for "OUT " prefix
        snprintf(buffer, sizeof(buffer), "OUT %s", output);
        send(socket_fd, buffer, strlen(buffer), 0);
        usleep(1000);
    }

    FILE* perr = fdopen(pfd[0], "r");
    if (perr == NULL) {
        perror("fdopen failed");
        pclose(pout);
        return -1;
    }

    while (fgets(output, sizeof(output), perr) != NULL) {
        // Send each error line to the socket
        char buffer[1028]; // +4 for "OUT " prefix
        snprintf(buffer, sizeof(buffer), "OUT %s", output);
        send(socket_fd, buffer, strlen(buffer), 0);
    }
    // Clean up
    pclose(pout);
    fclose(perr);
    return 0;
}
