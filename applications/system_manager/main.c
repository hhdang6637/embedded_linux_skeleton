#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "system_manager.h"

typedef struct {
    bool daemon;
} global_settings;

static global_settings settings = {
        .daemon = true
};

static void show_help(const char *app_name) {
    printf("Usage: %s [options]\n", app_name);
    printf("         -d: don't fork to the background.\n");
}

void parse_arguments(int argc, char const *argv[]) {
    int i = 0;

    while (++i < argc) {
        if (strcmp(argv[i], "-d") == 0) {
            settings.daemon = false;
        } else if (strcmp(argv[i], "-h") == 0) {
            show_help(argv[0]);
            exit(EXIT_SUCCESS);
        } else {
            fprintf(stderr, "Unknown option. Use '-h' for help.\n");
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char const *argv[])
{
    pid_t pid;

    parse_arguments(argc, argv);

    /* Become a daemon
     */
    if (settings.daemon) {
        switch (pid = fork()) {
        case -1:
            perror("fork()");
            return -1;
        case 0:
            if (setsid() == -1) {
                perror("setsid()");
                exit(EXIT_FAILURE);
                ;
            }
            break;
        default:
            printf("%s just fork to new proccess %d\n", argv[0], pid);
            return 0;
        }
    }

    system_manager_init();

    printf("%s init complete\n", argv[0]);

    while(1) {
        sleep(1);
    }

    return 0;
}
