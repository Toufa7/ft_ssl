NAME	= ft_ssl

GCC		= gcc

CFLAGS	= -Wall -Wextra -Werror -O0 -g3

ASAN	= -fsanitize=address

SRC		=	./srcs/main.c\
			./srcs/ft_md5.c\
			./srcs/ft_sha256.c\
			./utils/log.c\
			./srcs/ft_utils.c\

OBJ		= $(SRC:.c=.o)

BONUS	= $(SRC)\
			./srcs/ft_sha1.c\

BONUS_OBJ		= $(BONUS:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
	$(GCC) $(CFLAGS) $(ASAN) $(SRC) -o $(NAME)

bonus:
	$(GCC) -DBONUS $(BONUS) -o $(NAME)_bonus


debug:
	$(GCC) -DDEBUG -DLOG_USE_COLOR  $(ASAN) $(SRC) -o $(NAME)

clean:
	rm -rf $(NAME)

re:
	clean all

.PHONY: all re clean
