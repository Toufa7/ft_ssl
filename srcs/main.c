#include "../include/ft_ssl.h"
#include "../include/log.h"
#include "../include/ft_md5.h"
#include "../include/ft_sha256.h"

static const t_commands g_commands[] = {
    {"md5", {0}, md5},
    {"sha256", {0}, sha256},
    {NULL, {0}, NULL}
};

static const t_commands *findCommand(char *arg){
    if (strcmp(arg, "md5") == 0)
        return &g_commands[0];
    else if (strcmp(arg, "sha256") == 0)
        return &g_commands[1];
    else
        return NULL;
}

// TODO: think about we could combine a lot of options
static const t_options findOption(char *option)
{
    t_options opts = {0};
    if (strcmp(option, "-p") == 0) {
        opts.p = true;
        // Reading from stdin, print the input alongside the hash
        // ("42 is nice")= 35f1d6de0302e2086a4e472266efb3a9
    }
    if (strcmp(option, "-q") == 0) {
        opts.q = true;
        // Quite mode means print only the hash no more no less
    }
    if (strcmp(option, "-r") == 0) {
        opts.r = true;
        
    }
    if (strcmp(option, "-s") == 0) {
        opts.s = true;
        // Hashing the input string next to
    }
    return opts;
}

char *getInput(int ac, char *av[], const t_options options)
{
    log_debug("Getting input with options: p=%d, q=%d, r=%d, s=%d", options.p, options.q, options.r, options.s);
    if (options.p) {
        // Read from stdin
        char *input = NULL;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&input, &len, stdin)) != -1) {
            // TODO: Check wether we should keep the newline or not
            if (input[read - 1] == '\n') {
                input[read - 1] = '\0';
            }
            return input;
        }
    }
    else if (options.s) {
        return av[3];
    }
    else {
        return av[3];
    }
    return NULL;
}

int main(int ac, char *av[])
{
    if (ac < 2)
    {
        log_error("No command provided");
        log_info("Usage: ./ft_ssl <command> [options] [input]");
        return 1;
    }
    else
    {
        log_debug("Command provided: %s", av[1]);
        const t_commands *cmd = findCommand(av[1]);
        log_debug("Command found: %s", cmd ? cmd->name : "NULL");
        if (cmd == NULL) {
            log_error("Invalid command provided: %s", av[1]);
            return 1;
        }
        bool noOption = (av[2] == NULL) ? true : (av[2][0] == '-' ? false : true);
        if (noOption) {
            log_info("No options provided, calling the function with default options");
            return (cmd->hash_func(av[2], (t_options){0}));
        }
        t_options opts = findOption(av[2]);
        // TODO: We could have no options provided, but we should still call the function with default options
        if (opts.p == false && opts.q == false && opts.r == false && opts.s == false)
        {
            log_error("Invalid option provided");
            return 1;
        }
        else
        {
            log_info("Command found: %s with option %s", cmd->name, av[2]);
            // char *input = getInput(ac, av, opts);
            return (cmd->hash_func(av[3], opts));
        }
    }
cleanup:
    return 0;
}