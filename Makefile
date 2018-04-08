all: server client

server: server.c
	gcc -o server server.c  -I/opt/ssl/include/ -L/opt/ssl/lib/ -lcrypto

client: client.c
	gcc -o client client.c  -I/opt/ssl/include/ -L/opt/ssl/lib/ -lcrypto
