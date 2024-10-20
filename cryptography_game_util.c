/*
* Ido Kantor
* methods used in code for the game
 */
#include "cryptography_game_util.h"

#include <limits.h>


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
        usleep(1000);
    }
    // Clean up
    pclose(pout);
    fclose(perr);
    return 0;
}

int numPlaces (int n) {
    int r = 1;
    if (n < 0) n = (n == 0) ? INT_MAX: -n;
    while (n > 9) {
        n /= 10;
        r++;
    }
    return r;
}

int extract_tlength(const char *tlength_str) {
    // Skip "tlength:"
    const char *number_start = tlength_str + 8;
    char *end_ptr = strchr(number_start, ';');
    if (!end_ptr) {
        // If no delimiter found, it's an invalid format
        fprintf(stderr, "Invalid tlength format\n");
        return -1;
    }
    // Create a temporary buffer to store the number
    const size_t length = end_ptr - number_start;
    char temp[length + 1];
    strncpy(temp, number_start, length);
    temp[length] = 0;
    // Convert to integer
    return atoi(temp);
}

int8_t process_packet(const char *packets, char* packets_data, const ssize_t tlength) {
    // Make a copy of the packet for parsing
    const char delim = ';';
    const size_t rest_of_length = 9 + numPlaces(tlength); //-9 for tlength: + ; -amount of tlength digits
    char *packet = strndup(packets + rest_of_length, tlength - rest_of_length);
    if (!packet) {
        perror("Failed to allocate memory for buffer");
        return -1;
    }
    // Step 3: Parse the fields using the delimiter
    const char *type = strtok(packet, &delim);
    const char *length_str = strtok(NULL, &delim);
    const char *data = strtok(NULL, &delim);
    if(type && length_str && data) {
        if(strncmp(type, "type:", 5) == 0 && strncmp(length_str, "length:", 7) == 0) {
            strcat(packets_data, data + 5);
        }
        else {
            fprintf(stderr, "Invalid packet fields\n");
            return -1;
        }
    }
    else {
        fprintf(stderr, "Failed to parse packet fields\n");
        return -1;
    }
    free(packet);
    return 0;
}

int parse_received_packets(const char* received_packets, char* packets_data, const size_t packets_size) {
    const char* current = received_packets;
    size_t current_length = 0;
    while (*current && current_length < packets_size) {
        const char* tlength_str = strstr(current, "tlength:");
        if (tlength_str == NULL) {
            return -1;
        }
        const ssize_t tlength = extract_tlength(tlength_str);
        if(tlength <= 0) {
            printf("tlength is less than zero\n");
            return -1;
        }
        if(strlen(current) < tlength && tlength < packets_size) {
            printf("tlength is smaller than current length\n");
            return -1;
        }
        const int8_t check = process_packet(current, packets_data, tlength);
        if(check == -1) {
            return -1;
        }
        current += tlength;
        current_length += tlength;
    }
    return 0;
}
