#ifndef FLAG_FILE_H
#define FLAG_FILE_H

#include "cryptography_game_util.h"

int generate_random_path_name(char *path, size_t path_size);

int execute_command(const char *command);

void generate_random_string(char *buffer, size_t buf_size);

#endif //FLAG_FILE_H
