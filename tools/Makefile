LFLAGS= -g -lsodium

crypto: crypto.c
		rm -rf crypto
		rm -rf mesh_crypto
		gcc -o crypto crypto.c $(LFLAGS)
		gcc -o mesh_crypto mesh_crypto.c $(LFLAGS)

clean:
		rm -rf mesh_crypto
		rm -rf crypto
