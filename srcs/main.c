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
    if (strcmp(option, "-p") == 0)
        opts.p = true;
    if (strcmp(option, "-q") == 0)
        opts.q = true;
    if (strcmp(option, "-r") == 0)
        opts.r = true;
    if (strcmp(option, "-s") == 0)
        opts.s = true;
    return opts;
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
        const t_commands *cmd = findCommand(av[1]);
        if (cmd == NULL) {
            log_error("Invalid command provided: %s", av[1]);
            return 1;
        }
        bool noOption = av[2][0] == '-' ? false : true;
        if (noOption) {
            log_info("No options provided, calling the function with default options");
            return (cmd->hash_func(av[2], (t_options){0}));
        }
        t_options opts = findOption(av[2]);
        // TODO: We could have no options provided, but we should still call the function with default options
        if (opts.p == true || opts.q == true || opts.r == true || opts.s == true)
        {
            log_error("Invalid option provided");
            return 1;
        }
        else
        {
            log_info("Command found: %s with option %s", cmd->name, av[2]);
            return (cmd->hash_func(av[3], opts));
        }
    }
cleanup:
    return 0;
}