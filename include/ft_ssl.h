#ifndef FT_SSL_H
#define FT_SSL_H

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct s_target {
    bool is_string;
    char *string;
} t_target;

typedef struct s_options {
    bool p;
    bool q;
    bool r;
    bool s;
    bool x;
    t_target *targets;
    int target_count;
} t_options;

typedef void (*t_hash)(const char *data, size_t len, const char *label, bool is_string, const t_options options, bool is_file); 

typedef struct s_commands {
    char *name;
    t_options options;
    t_hash hash_func;
} t_commands;

#endif