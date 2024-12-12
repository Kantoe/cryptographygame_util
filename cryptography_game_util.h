/*
* Ido Kantor
* methods used in code for cryptography_game
 */
#ifndef CRYPTOGRAPHY_GAME_UTIL_H
#define CRYPTOGRAPHY_GAME_UTIL_H
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>
#include <limits.h>
#include "commands.h"
#include "networking.h"
#include "security.h"
#include "packet_parse_and_build.h"
/* Buffer size constants */
#define BUFFER_SIZE_CMD_MAX 400
#define BUFFER_SIZE_FULL_CMD 512
#define BUFFER_SIZE_OUTPUT 1024
#define BUFFER_SIZE_SEND 2048
#define BUFFER_SIZE_CD 512
#define ERR_BUFFER_SIZE 256

/* Message processing constants */
#define FINISH_RECEIVE -1
#define TLENGTH_LEN 9
#define BASE_10 10
#define LENGTH_CHECK 4
#define NUM_ZERO 4
#define EMPTY_DATA "tlength:34;type:OUT;length:0;data:"

/* Constants for socket configuration */
#define SOCKET_FLAG 0
#define NO_IP 0
#define PORT_RANGE_MIN 0
#define PORT_RANGE_MAX 65535
#define CHECK_IP 0

/* Constants for errors */
#define PIPE_ERR_CHECK 0
#define GENERAL_ERROR -1
#define STATUS_OKAY 0

#define PIPE_OUT 1
#define PIPE_ERR 0
#define BASE_TEN 10               // The base for dividing numbers
#define SINGLE_DIGIT_LIMIT 9      // Largest single-digit number
#define HANDLE_NEGATIVE(n) ((n) < 0 ? -(n) : (n))  // Convert to absolute value
#define HANDLE_ZERO(n) ((n) == 0 ? INT_MAX : (n))  // Handle special case for zero

#define SKIP_TLENGTH 8
#define NULL_CHAR_LEN 1
#define TYPE_LEN 5
#define LENGTH_LEN 7
#define DATA_LEN 5
#define NULL_CHAR 0
#define TLENGTH_CHECK 0
#define SEND_FLAG 0
#define RECEIVE_FLAG 0
#define CHECK_RECEIVE 0
#define NEXT_CD 1
#define CD_AND_SPACE_LEN 3
#define DIR_LENGTH_CHECK 1
#define DIR_EMPTY 0
#define BACKSPACE 1
#define CMP_EQUAL 0
#define PIPE_READ 0
#define MIN_VALID_LENGTH 0
#define LAST_CHAR_OFFSET 1
#define NULL_TERMINATOR_OFFSET 1

#endif
