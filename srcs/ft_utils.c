#include "../include/ft_utils.h"

void printHash(const char *algo, const char *hex, bool is_string, const t_options opt, bool is_file, const char *label)
{
    if (is_file) {
        if (opt.p) {
            if (opt.q)
                printf("%s\n%s\n", label, hex);
            else
                printf("(\"%s\")= %s\n", label, hex);
        }
        else
            printf("(stdin)= %s\n", hex);
        return;
    }

    if (is_string) {
        if (opt.q)
            printf("%s\n", hex);
        else if (opt.r)
            printf("%s \"%s\"\n", hex, label);
        else
            printf("%s (\"%s\") = %s\n", algo, label, hex);
    } else {
        if (opt.q)
            printf("%s\n", hex);
        else if (opt.r)
            printf("%s %s\n", hex, label);
        else
            printf("%s (%s) = %s\n", algo, label, hex);
    }
}