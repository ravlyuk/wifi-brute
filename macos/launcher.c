#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void die(const char *message) {
    fprintf(stderr, "wifi-connect: %s\n", message);
    exit(1);
}

static void fail_status(const char *when, PyStatus status) {
    fprintf(stderr, "wifi-connect: %s: %s\n", when, status.err_msg ? status.err_msg : "unknown error");
    exit(1);
}

static void attach_log(void) {
    const char *home = getenv("HOME");
    if (home == NULL) {
        return;
    }

    char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/Library/Logs/wifi-connect.log", home);
    FILE *log = fopen(log_path, "a");
    if (log == NULL) {
        return;
    }
    dup2(fileno(log), STDOUT_FILENO);
    dup2(fileno(log), STDERR_FILENO);
    fclose(log);
}

static void parent_dir(char *path) {
    char *slash = strrchr(path, '/');
    if (slash == NULL) {
        die("invalid path");
    }
    *slash = '\0';
}

int main(int argc, char **argv) {
    attach_log();

    char executable[PATH_MAX];
    uint32_t size = sizeof(executable);
    if (_NSGetExecutablePath(executable, &size) != 0) {
        die("cannot resolve executable path");
    }

    char resolved[PATH_MAX];
    if (realpath(executable, resolved) == NULL) {
        die("cannot canonicalize executable path");
    }

    char contents[PATH_MAX];
    strncpy(contents, resolved, sizeof(contents) - 1);
    contents[sizeof(contents) - 1] = '\0';
    parent_dir(contents);
    parent_dir(contents);

    char site[PATH_MAX];
    snprintf(site, sizeof(site), "%s/Resources/venv/lib/python3.13/site-packages", contents);

    PyStatus py_status;
    PyConfig config;
    PyConfig_InitPythonConfig(&config);
    config.parse_argv = 0;
    config.install_signal_handlers = 1;

    py_status = PyConfig_SetBytesString(&config, &config.program_name, resolved);
    if (PyStatus_Exception(py_status)) {
        fail_status("program_name", py_status);
    }
    py_status = PyConfig_SetBytesString(&config, &config.pythonpath_env, site);
    if (PyStatus_Exception(py_status)) {
        fail_status("pythonpath", py_status);
    }

    char *py_argv[] = {resolved};
    py_status = PyConfig_SetBytesArgv(&config, 1, py_argv);
    if (PyStatus_Exception(py_status)) {
        fail_status("argv", py_status);
    }

    py_status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(py_status)) {
        fail_status("initialize", py_status);
    }

    (void)argc;
    (void)argv;
    int failed = PyRun_SimpleString(
        "from wifi_connector.__main__ import main\n"
        "main()\n"
    );
    Py_Finalize();
    return failed == 0 ? 0 : 1;
}
