#ifndef FLAG_FILE_H
#define FLAG_FILE_H

#include "cryptography_game_util.h"

int generate_random_path_name(char *path, size_t path_size);

int create_or_delete_flag_file(const char *command);

#endif //FLAG_FILE_H
