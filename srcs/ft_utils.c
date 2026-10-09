#include "../include/ft_utils.h"

void printHash(const char *algo, const char *digest, bool is_string, const t_options opt, bool is_file, const char *label)
{
    if (is_file) {
        if (opt.p) {
            if (opt.q)
                printf("%s\n%s\n", label, digest);
            else
                printf("(\"%s\")= %s\n", label, digest);
        }
        else
            printf("(stdin)= %s\n", digest);
        return;
    }

    if (is_string) {
        if (opt.q)
            printf("%s\n", digest);
        else if (opt.r)
            printf("%s \"%s\"\n", digest, label);
        else
            printf("%s (\"%s\") = %s\n", algo, label, digest);
    } else {
        if (opt.q)
            printf("%s\n", digest);
        else if (opt.r)
            printf("%s %s\n", digest, label);
        else
            printf("%s (%s) = %s\n", algo, label, digest);
    }
}