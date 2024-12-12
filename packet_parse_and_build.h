#ifndef PACKET_PARSE_AND_BUILD_H
#define PACKET_PARSE_AND_BUILD_H
#include "cryptography_game_util.h"

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
 const char *received_packets, char *packets_data, char *packets_type, char *packets_length,
 size_t packets_size, size_t packets_length_size, ssize_t packets_data_size,
 size_t packets_type_size);

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
int8_t prepare_buffer(char *buffer, size_t buffer_size, const char *data, const char *type);

#endif //PACKET_PARSE_AND_BUILD_H
