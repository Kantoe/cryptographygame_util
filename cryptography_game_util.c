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

void execute_command(const char *command, char **buffer) {
    size_t buffer_size = CHUNK_SIZE;
    size_t total_length = 0;
    *buffer = malloc(buffer_size);

    if (*buffer == NULL) {
        perror("malloc failed");
        exit(1);
    }

    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        free(*buffer);
        exit(1);
    }

    size_t bytes_read;
    while ((bytes_read = fread(*buffer + total_length, 1, CHUNK_SIZE, fp)) > 0) {
        total_length += bytes_read;

        if (total_length >= buffer_size - 1) {
            buffer_size += CHUNK_SIZE;
            char* temp = realloc(*buffer, buffer_size);
            if (temp == NULL) {
                perror("realloc failed");
                free(*buffer);
                pclose(fp);
                exit(1);
            }
            *buffer = temp;
        }
    }
    (*buffer)[total_length] = '\0';  // Null-terminate the string
    pclose(fp);
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