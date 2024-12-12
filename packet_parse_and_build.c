#include "packet_parse_and_build.h"

//prototypes

/*
 * Calculates the number of decimal places in an integer
 * Parameters:
 *   n - The integer to analyze
 * Returns: Number of decimal places
 */
int numPlaces(int n);

/*
 * Extracts total length value from a tlength string field
 * Parameters:
 *   tlength_str - String containing the tlength field
 * Returns: Extracted length value or -1 on error
 */
int extract_tlength(const char *tlength_str);

/*
 * Validates packet fields and updates corresponding buffers
 * Parameters:
 *   packets_data - Buffer for packet data
 *   packets_type - Buffer for packet types
 *   packets_length - Buffer for packet lengths
 *   packets_length_size - Size of length buffer
 *   packets_data_size - Size of data buffer
 *   packets_type_size - Size of type buffer
 *   packet - Current packet being processed
 * Returns: 0 on success, -1 on failure
 */
int8_t check_packet_fields(char *packets_data, char *packets_type,
                           char *packets_length, size_t packets_length_size,
                           ssize_t packets_data_size, size_t packets_type_size,
                           char *packet);

/*
 * Processes a single packet by extracting and validating its fields
 * Parameters:
 *   packets - Raw packet data
 *   packets_data - Buffer for processed data
 *   packets_type - Buffer for packet types
 *   packets_length - Buffer for packet lengths
 *   tlength - Total length of packet
 *   packets_length_size - Size of length buffer
 *   packets_data_size - Size of data buffer
 *   packets_type_size - Size of type buffer
 * Returns: 0 on success, -1 on failure
 */
int8_t process_packet(
    const char *packets, char *packets_data, char *packets_type,
    char *packets_length, ssize_t tlength,
    size_t packets_length_size, ssize_t packets_data_size,
    size_t packets_type_size);

//methods

/*
 * Calculates the number of decimal places in an integer
 * Parameters:
 *   n - The integer to analyze
 * Returns: Number of decimal places
 */
int numPlaces(int n) {
    int r = 1; // Start with the minimum count of places
    if (n < 0) n = HANDLE_ZERO(HANDLE_NEGATIVE(n)); // Handle negative numbers and zero
    while (n > SINGLE_DIGIT_LIMIT) {
        // Loop until n is a single-digit number
        n /= BASE_TEN; // Divide by the base (10)
        r++;
    }
    return r;
}

/*
 * Extracts total length value from a tlength string field
 * Parameters:
 *   tlength_str - String containing the tlength field
 * Returns: Extracted length value or -1 on error
 */
int extract_tlength(const char *tlength_str) {
    // Skip "tlength:"
    const char *number_start = tlength_str + SKIP_TLENGTH;
    char *end_ptr = strchr(number_start, ';');
    if (!end_ptr) {
        // If no delimiter found, it's an invalid format
        fprintf(stderr, "Invalid tlength format\n");
        return GENERAL_ERROR;
    }
    // Create a temporary buffer to store the number
    const size_t length = end_ptr - number_start;
    char temp[length + NULL_CHAR_LEN];
    strncpy(temp, number_start, length);
    temp[length] = NULL_CHAR;
    // Convert to integer
    return atoi(temp);
}

/*
 * Validates packet fields and updates corresponding buffers
 * Parameters:
 *   packets_data - Buffer for packet data
 *   packets_type - Buffer for packet types
 *   packets_length - Buffer for packet lengths
 *   packets_length_size - Size of length buffer
 *   packets_data_size - Size of data buffer
 *   packets_type_size - Size of type buffer
 *   packet - Current packet being processed
 * Returns: 0 on success, -1 on failure
 */

int8_t check_packet_fields(char *packets_data, char *packets_type, char *packets_length,
                           const size_t packets_length_size, const ssize_t packets_data_size,
                           const size_t packets_type_size, char *packet) {
    char *type_start = strstr(packet, "type:");
    char *length_start = strstr(packet, "length:");
    char *data_start = strstr(packet, "data:");
    if (!type_start || !length_start || !data_start) {
        fprintf(stderr, "Failed to parse packet fields\n");
        free(packet);
        return GENERAL_ERROR;
    }
    // Extract type
    type_start += TYPE_LEN; // Skip "type:"
    char *type_end = strchr(type_start, ';');
    if (!type_end) {
        fprintf(stderr, "Invalid type field\n");
        free(packet);
        return GENERAL_ERROR;
    }
    *type_end = NULL_CHAR;
    // Extract length
    length_start += LENGTH_LEN; // Skip "length:"
    char *length_end = strchr(length_start, ';');
    if (!length_end) {
        fprintf(stderr, "Invalid length field\n");
        free(packet);
        return GENERAL_ERROR;
    }
    *length_end = NULL_CHAR;
    const int data_length = atoi(length_start);
    // Extract data
    data_start += DATA_LEN; // Skip "data:"
    // Verify data length matches specified length
    if (strlen(data_start) != data_length) {
        fprintf(stderr, "Data length mismatch. Expected %d, got %zu\n",
                data_length, strlen(data_start));
        free(packet);
        return GENERAL_ERROR;
    }
    // Add to packets_data if there's room
    if (packets_data_size >= strlen(packets_data) + strlen(data_start) + NULL_CHAR_LEN) {
        strcat(packets_data, data_start);
    }
    // Add to packets_type if there's room
    if (packets_type_size >= strlen(packets_type) + strlen(type_start) + NULL_CHAR_LEN) {
        strcat(packets_type, type_start);
        strcat(packets_type, ";");
    }

    // Add to packets_length if there's room
    if (packets_length_size >= strlen(packets_length) + strlen(length_start) + NULL_CHAR_LEN) {
        strcat(packets_length, length_start);
        strcat(packets_length, ";");
    }
    return STATUS_OKAY;
}


/*
 * Processes a single packet by extracting and validating its fields
 * Parameters:
 *   packets - Raw packet data
 *   packets_data - Buffer for processed data
 *   packets_type - Buffer for packet types
 *   packets_length - Buffer for packet lengths
 *   tlength - Total length of packet
 *   packets_length_size - Size of length buffer
 *   packets_data_size - Size of data buffer
 *   packets_type_size - Size of type buffer
 * Returns: 0 on success, -1 on failure
 */
int8_t process_packet(
    const char *packets, char *packets_data, char *packets_type,
    char *packets_length, const ssize_t tlength,
    const size_t packets_length_size, const ssize_t packets_data_size,
    const size_t packets_type_size) {
    // Make a copy of the packet for parsing
    const size_t total_tlength_len = TLENGTH_LEN + numPlaces(tlength);
    //-9 for tlength: + ; -amount of tlength digits
    char *packet = strndup(packets + total_tlength_len, tlength - total_tlength_len);
    if (!packet) {
        perror("Failed to allocate memory for buffer");
        return GENERAL_ERROR;
    }
    // Step 3: Parse the fields using the delimiter
    const int8_t check_fields = check_packet_fields(
        packets_data, packets_type,
        packets_length, packets_length_size,
        packets_data_size, packets_type_size, packet);
    if (check_fields != GENERAL_ERROR) {
        free(packet);
    }
    return check_fields;
}

/*
* Parses a received network packet stream into its component parts.
* This function processes a string of packets containing type, length,
* and data fields, separating them into their respective buffers.
* Validates packet format and ensures all fields are properly extracted.
* Parameters:
*   received_packets - Raw packet data string to parse
*   packets_data - Buffer to store extracted data fields
*   packets_type - Buffer to store packet type information
*   packets_length - Buffer to store length information
*   packets_size - Total size of received packets
*   packets_length_size - Size of length buffer
*   packets_data_size - Size of data buffer
*   packets_type_size - Size of type buffer
* Returns: 1 if parsing successful, 0 if any error occurs
*/
int parse_received_packets(
    const char *received_packets, char *packets_data, char *packets_type,
    char *packets_length,
    const size_t packets_size, const size_t packets_length_size,
    const ssize_t packets_data_size,
    const size_t packets_type_size) {
    const char *current = received_packets;
    size_t current_length = 0;
    while (*current && current_length < packets_size) {
        const char *tlength_str = strstr(current, "tlength:");
        if (tlength_str == NULL) {
            return false;
        }
        const ssize_t tlength = extract_tlength(tlength_str);
        if (tlength <= TLENGTH_CHECK) {
            printf("tlength is less than zero\n");
            return false;
        }
        if (strlen(current) < tlength) {
            printf("tlength is bigger than current length\n");
            return false;
        }
        const int8_t check = process_packet(current, packets_data, packets_type,
                                            packets_length, tlength,
                                            packets_length_size,
                                            packets_data_size,
                                            packets_type_size);
        if (check == GENERAL_ERROR) {
            return false;
        }
        current += tlength;
        current_length += tlength;
    }
    return current_length == packets_size;
}

/*
* Prepares a network message buffer with formatted data.
* Formats the message with proper protocol fields including total length,
* type, data length, and the data itself. Creates a complete packet
* ready for network transmission.
* Parameters:
*   buffer - Destination buffer for the formatted message
*   buffer_size - Size of the destination buffer
*   data - The actual data to be sent
*   type - Message type identifier (e.g., "OUT", "ERR", "CWD")
* Returns: 1 on success, 0 on failure
*/
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
        return false;
    }
    // Calculate tlength as the length of the formatted message (including "tlength:" part)
    const int message_length = snprintf(NULL, 0,
                                        "tlength:%d;type:%s;length:%d;data:%s",
                                        formatted_length, type, data_length,
                                        data);
    if (message_length >= buffer_size) {
        fprintf(stderr,
                "Buffer too small to store formatted message.\n");
        return false;
    }
    // Format the final message with correct tlength
    const int final_size = snprintf(buffer, buffer_size,
                                    "tlength:%d;type:%s;length:%d;data:%s",
                                    message_length, type, data_length, data);
    if (final_size >= buffer_size) {
        fprintf(stderr,
                "Buffer too small to store formatted message.\n");
        return false;
    }
    snprintf(buffer, buffer_size,
             "tlength:%d;type:%s;length:%d;data:%s",
             final_size, type, data_length, data);
    return true;
}
