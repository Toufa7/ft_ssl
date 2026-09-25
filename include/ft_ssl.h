#ifndef FT_SSL_H
#define FT_SSL_H

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct s_options {
    bool p;
    bool q;
    bool r;
    bool s;
} t_options;

typedef int (*t_hash)(char *input, const t_options options);

typedef struct s_commands {
    char *name;
    t_options options;
    t_hash hash_func;
} t_commands;















































#endif