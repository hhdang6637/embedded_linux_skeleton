#include <syslog.h>

#include <iostream>

#include "resource_manager.h"
#include "utilities.h"
#include "resource_manager.h"
#include "backtrace_signal.h"

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
    openlog(SERVICE_NAME, 0, LOG_USER);

    backtrace_init_signal();

    parse_arguments(argc, argv);

    if (settings.daemon) {
        if (daemon(1, 1)) {
            syslog(LOG_ERR, "fork is not scuccess");
            exit(EXIT_FAILURE);
        }
    }

    write_pid(PID_FILE_NAME, getpid());

    resource_manager_init();

    syslog(LOG_NOTICE,"%s init complete\n", SERVICE_NAME);

    resource_manager_service_loop();
    return 0;
}
