#include "../include/ft_ssl.h"
#include "../include/log.h"
#include "../include/ft_md5.h"
#include "../include/ft_sha256.h"
#include "../include/ft_sha1.h"

static const t_commands g_commands[] = {
    {"md5", {0}, md5},
    {"sha256", {0}, sha256},
#ifdef BONUS
    {"sha1", {0}, sha1},
#endif
    {NULL, {0}, NULL}
};

static const t_commands *findCommand(char *arg){
    for (size_t i = 0; g_commands[i].name != NULL; i++) {
        if (strcmp(arg, g_commands[i].name) == 0) {
            return &g_commands[i];
        }
    }
    return NULL;
}

t_options findOption(char *option)
{
    t_options opts = {0};
    if (strcmp(option, "-p") == 0) opts.p = true;
    else if (strcmp(option, "-q") == 0) opts.q = true;
    else if (strcmp(option, "-r") == 0) opts.r = true;
    else if (strcmp(option, "-s") == 0) opts.s = true;
    else opts.x = true;
    return opts;
}

t_options parseArgs(int ac, char *av[], int start, t_target *targets) {
    t_options opts = {0};
    opts.targets = targets;
    opts.target_count = 0;
    bool option_mode = true;
    int i = start;

    while (i < ac) {
#ifdef DEBUG
        log_debug("Parsing argument: [%s]", av[i]);
#endif
        if (option_mode && av[i][0] == '-') {
            t_options _opts = findOption(av[i]);
#ifdef DEBUG
            log_debug("Option found: [%s]= p: %d, q: %d, r: %d, s: %d, x: %d", av[i], _opts.p, _opts.q, _opts.r, _opts.s, _opts.x);
#endif
            opts.p |= _opts.p;
            opts.q |= _opts.q;
            opts.r |= _opts.r;
            if (_opts.s) {
                if (i + 1 < ac) {
#ifdef DEBUG
                    log_debug("Option -s found with argument: %s", av[i + 1]);
#endif
                    opts.targets[opts.target_count].is_string = true;
                    opts.targets[opts.target_count].string = av[i + 1];
                    opts.target_count++;
                    i++;
                } else {
                    fprintf(stderr, "ft_ssl: option -s requires an argument\n");
                    break;
                }
            }
            else if (_opts.x) {
                fprintf(stderr, "ft_ssl: illegal option -- %s\n", av[i]);
            }
            i++;
            continue;
        }
        else
        {
            option_mode = false;
            opts.targets[opts.target_count].is_string = false;
            opts.targets[opts.target_count].string = av[i];
            opts.target_count++;
            i++;
        }
    }
    return opts;
}

static char *getInput(size_t *len) {
    size_t bufsize = 1024;
    char *buffer = malloc(bufsize);
    if (!buffer) {
#ifdef DEBUG
        log_error("ft_ssl: Memory allocation failed");
#endif
        return NULL;
    }

    size_t n = 0;
    while ((n = fread(buffer + *len, 1, bufsize - *len, stdin)) > 0) {
        *len += n;
        if (*len == bufsize) {
            bufsize *= 2;
            char *new_buffer = realloc(buffer, bufsize);
            if (!new_buffer) {
#ifdef DEBUG
                log_error("ft_ssl: Memory allocation failed");
#endif
                free(buffer);
                return NULL;
            }
            buffer = new_buffer;
        }
    }
    buffer[*len] = '\0';
    return buffer;
}

void runHash(const t_commands *cmd, const t_options options) {
    if (options.p || options.target_count == 0) {
        size_t len = 0;
        char *input = getInput(&len);
        if (input) {
            // Label only used for printing the hash result (display only) (input)= hash 
            char *label = strdup(input);
            if (len > 0 && label[len - 1] == '\n') {
                label[len - 1] = '\0';
            }
            cmd->hash_func(input, len, label, false, options, true);
            free(input);
            free(label);
        }
    }

    for (int i = 0; i < options.target_count; i++) {
        t_target targets = options.targets[i];
#ifdef DEBUG
        log_debug("Processing target: [%s] which is %s", targets.string, targets.is_string ? "a string" : "a file");
#endif
        if (targets.is_string) {
            cmd->hash_func(targets.string, strlen(targets.string), targets.string, true, options, false);
        }
        else
        {
            FILE *file = fopen(targets.string, "rb");
            if (!file) {
                fprintf(stderr, "ft_ssl: %s: No such file or directory\n", targets.string);
                continue;
            }
            fseek(file, 0, SEEK_END);
            long len = ftell(file);
            fseek(file, 0, SEEK_SET);
            char *buffer = malloc(len + 1);
            if (!buffer) {
#ifdef DEBUG
                log_error("ft_ssl: Memory allocation failed");
#endif            
                fclose(file);
                continue;
            }
            fread(buffer, 1, len, file);
            buffer[len] = '\0';
            fclose(file);

            cmd->hash_func(buffer, len, targets.string, false, options, false);
            free(buffer);
        }
    }
}


int getCmdFromSTDIN() {
    char command[256];
    if (fgets(command, sizeof(command), stdin) == NULL) {
        fprintf(stderr, "ft_ssl: failed to read command from stdin\n");
        return 1;
    }
    size_t len = strlen(command);
    if (len > 0 && command[len - 1] == '\n') {
        command[len - 1] = '\0';
    }

    const t_commands *cmd = findCommand(command);
    if (cmd == NULL) {
        fprintf(stderr, "ft_ssl: invalid command provided: %s\n", command);
        return 1;
    }

    t_options _opts = {0};
    runHash(cmd, _opts);
    return 0;
}

int main(int ac, char *av[])
{
    if (ac < 2) {
#ifdef BONUS
        return getCmdFromSTDIN();
#endif
        fprintf(stderr, "Usage: ./ft_ssl <command> [options] [input]\n");
        return 1;
    }
    else
    {
        const t_commands *cmd = findCommand(av[1]);
        if (cmd == NULL) {
            fprintf(stderr, "ft_ssl: invalid command provided: %s\n", av[1]);
            return 1;
        }
        t_target targets[ac > 2 ? ac - 2 : 1    ];
        t_options _opts = parseArgs(ac, av, 2, targets);
        runHash(cmd, _opts);
        return 0;
    }
}