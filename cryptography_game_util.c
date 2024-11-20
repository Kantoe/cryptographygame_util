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

int execute_command_and_send(const char* command, const size_t command_size ,const int socket_fd) {
    int pfd[2];  // Pipe file descriptors
    if (pipe(pfd) < 0) {
        perror("pipe failed");
        return -1;
    }
    if(command_size > 256) {
        fprintf(stderr, "command size too large\n");
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
        char buffer[2048] = {0};
        prepare_buffer(buffer, sizeof(buffer), output, "OUT");
        send(socket_fd, buffer, strlen(buffer), 0);
    }

    FILE* pipe_err = fdopen(pfd[0], "r");
    if (pipe_err == NULL) {
        perror("fdopen failed");
        pclose(pout);
        return -1;
    }

    while (fgets(output, sizeof(output), pipe_err) != NULL) {
        // Send each error line to the socket
        char buffer[2048] = {0};
        prepare_buffer(buffer, sizeof(buffer), output, "OUT");
        send(socket_fd, buffer, strlen(buffer), 0);
    }
    // Clean up
    pclose(pout);
    fclose(pipe_err);
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

/*
 * takes a single packet and processes it by its fields
 * appending them to a pointer of all packets fields
 */

int8_t process_packet(
    const char *packets, char* packets_data, char* packets_type, char* packets_length, const ssize_t tlength,
    const size_t packets_length_size, const ssize_t packets_data_size, const size_t packets_type_size) {
    // Make a copy of the packet for parsing
    const size_t rest_of_length = 9 + numPlaces(tlength); //-9 for tlength: + ; -amount of tlength digits
    char *packet = strndup(packets + rest_of_length, tlength - rest_of_length);
    if (!packet) {
        perror("Failed to allocate memory for buffer");
        return -1;
    }
    // Step 3: Parse the fields using the delimiter
    const char *type = strtok(packet, ";");
    const char *data_length = strtok(NULL, ";");
    const char *data = strtok(NULL, ";");
    if(type && data_length && data) {
        if(strncmp(type, "type:", 5) == 0 && strncmp(data_length, "length:", 7) == 0) {
            if(packets_data_size >= strlen(packets_data) + strlen(data)) {
                strcat(packets_data, data + 5);
            }
            if(packets_type_size >= strlen(packets_type) + strlen(type) + 1) {
                strcat(packets_type, type + 5);
                strcat(packets_type, ";");
            }
            if(packets_length_size >= strlen(packets_length) + strlen(data_length) + 1) {
                strcat(packets_length, data_length + 7);
                strcat(packets_length, ";");
            }
        }
        else {
            //fprintf(stderr, "Invalid packet fields\n");
            free(packet);
            return -1;
        }
    }
    else {
        //fprintf(stderr, "Failed to parse packet fields\n");
        free(packet);
        return -1;
    }
    free(packet);
    return 0;
}

int parse_received_packets(
    const char* received_packets, char* packets_data, char* packets_type, char* packets_length,
    const size_t packets_size, const size_t packets_length_size, const ssize_t packets_data_size,
    const size_t packets_type_size) {
    const char* current = received_packets;
    size_t current_length = 0;
    while (*current && current_length < packets_size) {
        const char* tlength_str = strstr(current, "tlength:");
        if (tlength_str == NULL) {
            return 0;
        }
        const ssize_t tlength = extract_tlength(tlength_str);
        if(tlength <= 0) {
            printf("tlength is less than zero\n");
            return 0;
        }
        if(strlen(current) < tlength) {
            printf("tlength is bigger than current length\n");
            return 0;
        }
        const int8_t check = process_packet(current, packets_data, packets_type,
                                            packets_length, tlength, packets_length_size,
                                            packets_data_size, packets_type_size);
        if(check == -1) {
            return 0;
        }
        current += tlength;
        current_length += tlength;
    }
    return current_length == packets_size;
}

int8_t prepare_buffer(
    char *buffer, const size_t buffer_size,
    const char *data, const char *type) {
    // Calculate the length of the data
    const int data_length = strlen(data);

    // Format the message without tlength first, so we can calculate it later
    const int formatted_length = snprintf(buffer, buffer_size,
        "tlength:;type:%s;length:%d;data:%s",
        type, data_length, data);

    // If formatting fails or message is too large, return
    if (formatted_length >= buffer_size) {
        fprintf(stderr,
            "Buffer too small to store formatted message.\n");
        return 0;
    }
    // Calculate tlength as the length of the formatted message (including "tlength:" part)
    const int message_length = snprintf(NULL, 0,
        "tlength:%d;type:%s;length:%d;data:%s",
        formatted_length, type, data_length, data);

    // Format the final message with correct tlength
    snprintf(buffer, buffer_size,
        "tlength:%d;type:%s;length:%d;data:%s",
        message_length, type, data_length, data);
    return 1;
}

int send(int socket, char * data, size_t data_size) {

    return 0;
}

int recv(int socket, char * data, size_t data_size) {
    return 0;
}
/*
    def send(my_socket, data):
        """gets data in string and a socket and sends
        the data back with the length also encoded
        in the first 4 bytes and if the length isn't big enough
        it fills the remaining bytes with a zero
        and then the data encoded"""
        encoded_data = data.encode()
        length = len(encoded_data)
        length_string = str(length)
        full_length_string = length_string.zfill(NUM_ZERO)
        length_byte = full_length_string.encode()
        my_socket.send(length_byte + encoded_data)

    @staticmethod
    def recv(my_socket):
        """receives a socket and receives data in two parts the first one receives
        the first four bytes containing the length of the other data
        the second receives the data until it's all received
        by knowing if the length of the data received
        meets the size received in the first for bytes
        then it returns all the data received without its length decoded"""
        raw_size = b''
        total_data = b''
        while len(raw_size) < LENGTH_CHECK:
            raw_size += my_socket.recv(RECEIVE_LENGTH - len(raw_size))
            if raw_size == FINISH_RECEIVE:
                return ''
        data_size = raw_size.decode()
        size = int(data_size)
        if data_size.isdigit():
            while size > SIZE_CHECK:
                data = my_socket.recv(size)
                size -= len(data)
                total_data += data
        return total_data.decode()
 */