# ECE361 Conputer Networks - Lab1: File Transfer Lab
# This is a simple makefile that compiles server.c and deliver.c
#
# Louis Chen		1000303502
# Chia-Hang Chang


# tools
CC := gcc
RM := rm -f

# flags
#CFLAGS := -ggdb
LDFLAGS :=
LDLIBS :=

# sources
sources := server.c deliver.c
targets := $(sources:.c=)

# targets
default: all
all: $(targets)

clean:
	$(RM) $(targets) $(sources:.c=.o)

