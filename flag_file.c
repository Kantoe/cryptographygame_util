#include "flag_file.h"

#include <sys/stat.h>

const char *random_directories[] = {"/home/", "/media/", "/dev/", "/opt/", "/usr/", "/lib/"};
const int num_directories = sizeof(random_directories) / sizeof(random_directories[0]);

void generate_random_string(char *buffer, const size_t buf_size) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const size_t charset_size = strlen(charset);
    // Map random bytes directly into the character set
    for (size_t i = 0; i < buf_size; i++) {
        buffer[i] = charset[arc4random_uniform(charset_size)];
    }
    buffer[buf_size] = NULL_CHAR; // Null-terminate the string
}

int check_permissions(const char *path) {
    return access(path, W_OK) == 0 ? STATUS_OKAY : GENERAL_ERROR;
}

int get_paths_number(const char *selected_directory) {
    char find_paths_command[128] = {0};
    if (snprintf(find_paths_command, sizeof(find_paths_command),
                 "find %s -type d | wc -l",
                 selected_directory) >= sizeof(find_paths_command)) {
        return GENERAL_ERROR;
    }
    FILE *fp = popen(find_paths_command, "r");
    if (fp == NULL) {
        return GENERAL_ERROR;
    }
    char paths_number[32] = {0};
    if (fgets(paths_number, sizeof(paths_number), fp) == NULL) {
        pclose(fp);
        return GENERAL_ERROR;
    }
    pclose(fp);
    return atoi(paths_number);
}

int generate_random_path_name(char *path, const size_t path_size) {
    while (1) {
        const uint32_t random_dir_index = arc4random_uniform(num_directories);
        const char *selected_dir = random_directories[random_dir_index];
        const int paths_number = get_paths_number(selected_dir);
        if (paths_number == GENERAL_ERROR) {
            return GENERAL_ERROR;
        }
        const uint32_t random_path_number = arc4random_uniform(paths_number) + 1;
        char get_path_command[128] = {0};
        if (snprintf(get_path_command, sizeof(get_path_command),
                     "find %s -type d | sed -n '%dp'",
                     selected_dir, random_path_number) >= sizeof(get_path_command)) {
            return GENERAL_ERROR;
        }
        FILE *pp = popen(get_path_command, "r");
        if (pp == NULL) {
            return GENERAL_ERROR;
        }
        memset(path, 0, path_size);
        if (fgets(path, path_size, pp) == NULL) {
            pclose(pp);
            return GENERAL_ERROR;
        }
        path[strlen(path) - 1] = 0; //remove newline
        pclose(pp);
        if (!strchr(path, ' ') && check_permissions(path) == STATUS_OKAY) {
            break;
        }
    }
    return STATUS_OKAY;
}

int create_or_delete_flag_file(const char *command) {
    if (command == NULL) {
        return GENERAL_ERROR;
    }
    if (strlen(command) == 0) {
        return GENERAL_ERROR;
    }
    // Execute command
    const int ret = system(command);
    // Case 1: Failed to create child process or get status
    if (ret == -1) {
        return GENERAL_ERROR;
    }
    // Case 2: Shell execution failed in child process
    if (WIFEXITED(ret) && WEXITSTATUS(ret) == 127) {
        return GENERAL_ERROR;
    }
    // Case 3: Normal termination - check exit status
    if (WIFEXITED(ret)) {
        const int exit_status = WEXITSTATUS(ret);
        if (exit_status != 0) {
            return GENERAL_ERROR;
        }
        return STATUS_OKAY; // Success case
    }
    // Case 4: Terminated by signal
    if (WIFSIGNALED(ret)) {
        return GENERAL_ERROR;
    }
    return GENERAL_ERROR;
}
