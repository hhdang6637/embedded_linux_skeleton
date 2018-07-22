#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>

#include <iostream>

#include "system_manager.h"

typedef struct {
    bool daemon;
} global_settings;

static global_settings settings = {
        .daemon = true
};

static void show_help(const char *app_name) {
    std::cout << "Usage: " << app_name << " [options]\n";
    std::cout << "         -d: don't fork to the background.\n";
}

void parse_arguments(int argc, char const *argv[]) {
    int i = 0;

    std::string debug_flag("-d");
    std::string help_flag("-h");

    while (++i < argc) {
        if (debug_flag.compare("-d") == 0) {
            settings.daemon = false;
        } else if (help_flag.compare("-h") == 0) {
            show_help(argv[0]);
            exit(EXIT_SUCCESS);
        } else {
            std::cerr << "Unknown option. Use '-h' for help.\n";
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char const *argv[])
{
    openlog(argv[0], 0, LOG_USER);

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
            std::cout << argv[0] << " just fork to new process " << pid << "\n";
            return 0;
        }
    }

    system_manager_init();

    std::cout << argv[0] << " init complete\n";

    while(1) {
        sleep(1);
    }

    return 0;
}
