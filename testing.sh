#!/bin/bash

GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"

TESTS=0
FAILED=0

check()
{
	TESTS=$((TESTS + 1))

	if [ "$1" = "$2" ]; then
		echo -e "${GREEN}OK${RESET}  $3"
	else
		echo -e "${RED}KO${RESET}  $3"
		echo "Expected:"
		printf '%s\n' "$2"
		echo "Got:"
		printf '%s\n' "$1"
		echo
		FAILED=$((FAILED + 1))
	fi
}

echo "And above all," > file

# stdin
REF=$(echo "42 is nice" | openssl md5)
GOT=$(echo "42 is nice" | ./ft_ssl md5)
check "$GOT" "$REF" "stdin"

# -p
REF=$(echo "42 is nice" | openssl md5)
GOT=$(echo "42 is nice" | ./ft_ssl md5 -p)
echo "$GOT"

# -q -r
REF=$(echo "Pity the living." | openssl md5 | awk '{print $2}')
GOT=$(echo "Pity the living." | ./ft_ssl md5 -q -r)
check "$GOT" "$REF" "-q -r"

# file
REF=$(openssl md5 file)
GOT=$(./ft_ssl md5 file)
check "$GOT" "$REF" "file"

# -r file
REF=$(openssl md5 -r file)
GOT=$(./ft_ssl md5 -r file)
check "$GOT" "$REF" "-r file"

# -s
TEXT="pity those that aren't following baerista on spotify."
REF=$(printf "%s" "$TEXT" | openssl md5)
GOT=$(./ft_ssl md5 -s "$TEXT")

# OpenSSL and ft_ssl have different formatting, so compare only the hash
REF=$(echo "$REF" | awk '{print $2}')
GOT=$(echo "$GOT" | awk '{print $NF}')
check "$GOT" "$REF" "-s"

# -p file
REF1=$(echo "be sure to handle edge cases carefully" | openssl md5 | awk '{print $2}')
REF2=$(openssl md5 file | awk '{print $2}')

GOT=$(echo "be sure to handle edge cases carefully" | ./ft_ssl md5 -p file)
echo "$GOT"

# stdin + file
REF=$(openssl md5 file)
GOT=$(echo "some of this will not make sense at first" | ./ft_ssl md5 file)
check "$GOT" "$REF" "stdin + file"

# -p -r file
REF=$(openssl md5 file -r | awk '{print $1}')
GOT=$(echo "but eventually you will understand" | ./ft_ssl md5 -p -r file)
echo "$GOT"

# -p -s file
REF_FILE=$(openssl md5 file)
REF_STRING=$(printf "%s" "foo" | openssl md5 | awk '{print $2}')

GOT=$(echo "GL HF let's go" | ./ft_ssl md5 -p -s "foo" file)
echo "$GOT"

# complex case
GOT=$(echo "one more thing" | ./ft_ssl md5 -r -p -s "foo" file -s "bar" 2>&1)
echo "$GOT"

# -r -q -p -s file
GOT=$(echo "just to be extra clear" | ./ft_ssl md5 -r -q -p -s "foo" file)
echo "$GOT"

echo
echo "$TESTS tests, $FAILED failed"

rm -f file
