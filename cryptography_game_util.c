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

int execute_command(const char *command, char **buffer) {
    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        return -1;
    }
    if(fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek failed");
        pclose(fp);
        return -1;
    }
    const long size = ftell(fp);
    if(size < 0) {
        perror("ftell failed");
        pclose(fp);
        return -1;
    }
    rewind(fp);
    *buffer = malloc(size + 1);
    if(*buffer == NULL) {
        perror("malloc failed");
        pclose(fp);
        return -1;
    }
    size_t bytes_read = 0;
    while(bytes_read < size) {
        bytes_read += fread(*buffer, 1, size, fp);
    }
    (*buffer)[size] = 0;  // Null-terminate the string
    pclose(fp);
    return 0;
}

void exe_command(const char* command, const int socket_fd) {
    FILE* fp = popen(command, "r");  // Open the command for reading
    if (fp == NULL) {
        perror("popen failed");
        exit(1);
    }
    char buffer[256];
    // Read each line from the command output
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        send(socket_fd, buffer, strlen(buffer), 0);
    }
    pclose(fp);  // Close the file pointer
}