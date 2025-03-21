#variables
CC = gcc
CFLAGS = -Wall -Wno-unused-variable -Wno-unused-function
SRCDIR = ./src/
BUILDDIR = ./build/
OBJ = $(BUILDDIR)main.o $(BUILDDIR)server_client.o $(BUILDDIR)message_queue.o $(BUILDDIR)encrypt_decrypt.o $(BUILDDIR)receiver.o $(BUILDDIR)sender.o
EXEC = run

.SILENT:

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto -lssl

$(BUILDDIR)%.o: $(SRCDIR)%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)