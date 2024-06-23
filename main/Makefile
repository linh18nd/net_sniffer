# Makefile for packet_sender

CC = gcc
CFLAGS = -Wall

main: main.c
	$(CC) $(CFLAGS) -o main main.c
	$(CC) $(CFLAGS) -o send_packet send_packet.c
	$(CC) $(CFLAGS) -o server server.c

clean:
	rm -f main send_packet server
