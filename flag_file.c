#include "flag_file.h"

#include <errno.h>

const char *random_directories[] = {"/home/", "/media/", "/dev/", "/opt/", "/usr/", "/lib/"};
const int num_directories = sizeof(random_directories) / sizeof(random_directories[0]);

int get_paths_number(const char *selected_directory) {
    char find_paths_command[128] = {0};
    if (snprintf(find_paths_command, sizeof(find_paths_command),
                 "find %s -maxdepth 7 -type d | wc -l",
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
    const uint32_t random_dir_index = arc4random_uniform(num_directories);
    const char *selected_dir = random_directories[random_dir_index];
    const int paths_number = get_paths_number(selected_dir);
    if (paths_number == GENERAL_ERROR) {
        return GENERAL_ERROR;
    }
    while (1) {
        const uint32_t random_path_number = arc4random_uniform(paths_number) + 1;
        char get_path_command[128] = {0};
        if (snprintf(get_path_command, sizeof(get_path_command),
                     "find %s -maxdepth 7 -type d | sed -n '%dp'",
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
        if (!strchr(path, ' ')) {
            break;
        }
    }
    return STATUS_OKAY;
}

int create_flag_file(const char *command) {
    printf("%d\n", getuid());
    if (command == NULL) {
        return GENERAL_ERROR;
    }
    if (strlen(command) == 0) {
        return GENERAL_ERROR;
    }
    // Execute command
    const int ret = system(command);
    printf("%d\n", getuid());

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
