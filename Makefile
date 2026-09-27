NAME	= ft_ssl

GCC		= gcc

CFLAGS	= -Wall -Wextra -Werror 

ASAN	= -fsanitize=address

SRC		=	./srcs/main.c\
			./srcs/ft_md5.c\
			./srcs/ft_sha256.c\
			./utils/log.c\

all	= $(NAME)

$(NAME):
	$(GCC)  $(ASAN) $(SRC) -o $(NAME)

debug:
	$(GCC) -DDEBUG -DLOG_USE_COLOR  $(ASAN) $(SRC) -o $(NAME)


clean:
	rm -rf $(NAME)

re:
	clean all

.PHONY: all re clean
