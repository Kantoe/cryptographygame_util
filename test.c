#include <time.h>
#include <sys/time.h>
#include "cryptography_game_util.h"

int main() {
    struct timeval real_start, real_end;
    gettimeofday(&real_start, NULL);
    const clock_t start = clock();
    const int socket = createTCPIpv4Socket();
    struct sockaddr_in address;
    createIPv4Address("127.0.0.1", 2000, &address);
    connect(socket, (struct sockaddr *)&address,sizeof(address));
    for(int i = 0; i < 5000; i++) {
        char* buffer = NULL;
        execute_command("cat /home/idokantor/test.txt", &buffer);
        if(buffer != NULL) {
            send(socket, buffer, strlen(buffer), 0);
            free(buffer);
        }
    }
    close(socket);
    gettimeofday(&real_end, NULL);
    const clock_t end = clock();
    const double time_spent = (double) (end - start) / CLOCKS_PER_SEC;
    const double seconds = (real_end.tv_sec - real_start.tv_sec) +
                       (real_end.tv_usec - real_start.tv_usec) / 1000000.0;
    printf("CPU time spent: %f\n", time_spent);
    printf("Real time spent: %f\n", seconds);
    return 0;
}
