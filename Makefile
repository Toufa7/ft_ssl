NAME	=	ft_ssl

NAME_	=	ft_ssl_bonus

GCC		=	gcc

CFLAGS	=	-Wall -Wextra -Werror -g3

ASAN	= 	-fsanitize=address

SRC		=	./srcs/main.c\
			./srcs/ft_md5.c\
			./srcs/ft_sha256.c\
			./srcs/ft_utils.c\

OBJ		= 	$(SRC:.c=.o)

BONUS	=	$(SRC)\
			./srcs/ft_sha1.c\
			./srcs/ft_sha512.c\

BONUS_OBJ=	$(BONUS:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
		$(GCC) $(CFLAGS) $(ASAN) $(SRC) -o $(NAME)

bonus:
	$(GCC) -DBONUS $(BONUS) -o $(NAME)_bonus

debug:
	$(GCC) -DDEBUG $(ASAN) $(SRC) -o $(NAME)

clean:
	rm -rf $(OBJ) $(BONUS_OBJ)

fclean: clean
	rm -rf $(NAME) $(NAME_)

re: clean all

.PHONY: all re clean fclean 