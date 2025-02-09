#include <openssl/aes.h>

#include "aes_encryption.h"
#include "cryptography_game_util.h"
#include "flag_file.h"

int main() {
    /*const char *data1 = "ls /home&& rm test.txt";
    const char *data2 = "ls /home&& 0";
    const char *data3 = "ls /home&& ls /etc";
    const char *data4 = "ls /home&& ls /home/idokantor && cd /";
    const char *data5 = "rm test.txt";
    printf("Check data1: %d\n", check_command_data(data1)); // Should return 0
    printf("Check data2: %d\n", check_command_data(data2)); // Should return 0
    printf("Check data3: %d\n", check_command_data(data3)); // Should return 0
    printf("Check data4: %d\n", check_command_data(data4)); // Should return 1
    printf("Check data5: %d\n", check_command_data(data5)); // Should return 0*/
    /*char buffer[1024];
    prepare_buffer(buffer, sizeof(buffer), "\nWait for second client to connect\n",
                   "KEY");
    printf("%s\n", buffer);*/
    /*char buffer[1024] = {0};
    generate_random_path_name(buffer, 1024);
    printf("%s\n", buffer);
    char temp[2048] = {0};*/
    /*char random[33] = {0};
    generate_random_string(random, 32);
    printf("%s\n", random);*/
    /*snprintf(temp, 2048, "echo '%s' > %s/flag.txt", random, buffer);
    if (create_or_delete_flag_file(temp) == STATUS_OKAY) {
        printf("good");
    }*/
    // Test message
    const char *message = "ls /home";
    const size_t message_len = strlen(message);
    // Fixed key for testing (32 bytes for AES-256)
    unsigned char key[32] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
    };
    // Encrypt
    size_t encrypted_len;
    char *encrypted = aes_encrypt(key, (unsigned char *) message, message_len, &encrypted_len);
    if (!encrypted) {
        printf("Encryption failed\n");
        return 1;
    }
    printf("Original: %s\n", message);
    printf("Encrypted (base64): %s\n", encrypted);
    // Decrypt
    size_t decrypted_len;
    unsigned char *decrypted = aes_decrypt(key, encrypted, encrypted_len, &decrypted_len);
    if (!decrypted) {
        printf("Decryption failed\n");
        free(encrypted);
        return 1;
    }
    // Add null terminator for printing
    char *decrypted_str = malloc(decrypted_len + 1);
    memcpy(decrypted_str, decrypted, decrypted_len);
    decrypted_str[decrypted_len] = '\0';

    printf("Decrypted: %s\n", decrypted_str);
    // Clean up
    free(encrypted);
    free(decrypted);
    free(decrypted_str);
    return 0;
}

/*
 * comment this code, don't change any logic of the code and add macros in the code for constants.
 * also if a constant is already in the code don't change it for a different constant. again don't change any code logic,
 * don't comment too much try to add comments based on how the code is already commented if there are comments missing
 * add more inside functions don't comment too much. a good rule of thumb for comments inside functions is every 5 lines add a comment
 * each prototype comment like this style.
 /*
 * Processes received data from the server based on message type.
 * This function handles three different message types: OUT (output),
 * CMD (commands), and ERR (errors). It parses incoming messages and
 * processes each segment according to its type and length.
 * Parameters:
 *   socketFD - The socket file descriptor
 *   data - Buffer containing the message data
 *   type - Buffer containing message type information
 *   length - Buffer containing message length information
 * Returns: None
 */
