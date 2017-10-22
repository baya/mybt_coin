dbj_pack_objs = debug_beej_pack.o beej_pack.o
btc_ver_objs = btc_version.o beej_pack.o kyk_sha.o kyk_socket.o btc_message.o
btc_verack_objs = btc_verack.o beej_pack.o kyk_sha.o kyk_socket.o btc_message.o
btc_echo_objs = btc_echo.o beej_pack.o kyk_sha.o kyk_socket.o btc_message.o
i_paths = /usr/local/opt/openssl/include
l_paths = /usr/local/opt/openssl/lib

debug_btc_version: CCFLAGS += -D DEBUG -g
debug_btc_version: btc_version

debug_beej_pack.out: $(dbj_pack_objs)
	gcc -o debug_beej_pack.out $(dbj_pack_objs)
debug_beej_pack.o: debug_beej_pack.c beej_pack.h
	gcc -c debug_beej_pack.c

btc_version: $(btc_ver_objs)
	$(CC) $(CCFLAGS) -o btc_version.out $(btc_ver_objs) -L$(l_paths) -lcrypto

btc_verack: $(btc_verack_objs)
	$(CC) $(CCFLAGS) -o btc_verack.out $(btc_verack_objs) -L$(l_paths) -lcrypto

btc_echo: $(btc_echo_objs)
	$(CC) $(CCFLAGS) -o btc_echo.out $(btc_echo_objs) -L$(l_paths) -lcrypto

beej_pack.o: beej_pack.c beej_pack.h
	$(CC) $(CCFLAGS) -c beej_pack.c

kyk_sha.o: kyk_sha.c kyk_sha.h
	$(CC) $(CCFLAGS) -c kyk_sha.c -I$(i_paths)

kyk_socket.o: kyk_socket.c kyk_socket.h btc_message.h
	$(CC) $(CCFLAGS) -c kyk_socket.c

btc_message.o: btc_message.c btc_message.h
	$(CC) $(CCFLAGS) -c btc_message.c

btc_version.o: btc_version.c beej_pack.h kyk_sha.h btc_message.h kyk_socket.h
	$(CC) $(CCFLAGS) -c btc_version.c -I$(i_paths)

btc_verack.o: btc_verack.c beej_pack.h kyk_sha.h btc_message.h kyk_socket.h
	$(CC) $(CCFLAGS) -c btc_verack.c -I$(i_paths)

btc_echo.o: btc_echo.c beej_pack.h kyk_sha.h btc_message.h kyk_socket.h
	$(CC) $(CCFLAGS) -c btc_echo.c -I$(i_paths)

debug_hashblock.out: debug_hashblock.o kyk_sha.o
	cc -o -W -Wall debug_hashblock.out debug_hashblock.o kyk_sha.o -L$(l_paths) -lcrypto 

debug_hashblock.o: debug_hashblock.c kyk_sha.h
	cc -c debug_hashblock.c -I$(i_paths)



clean:
	-rm -f debug_beej_pack.out $(dbj_pack_objs) $(btc_ver_objs) $(btc_verack_objs)