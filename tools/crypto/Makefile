CFLAGS= -Iinclude
LFLAGS= -g #-lsodium

SRC=src
BUILD=build

mesh_crypto: $(BUILD)/crypto.o $(BUILD)/sodium.o
	gcc -o mesh_crypto $(BUILD)/crypto.o $(BUILD)/sodium.o

$(BUILD)/crypto.o: $(SRC)/mesh_crypto.c
	gcc $(CFLAGS) -c -o $(BUILD)/crypto.o $(SRC)/mesh_crypto.c $(LFLAGS)

$(BUILD)/sodium.o: src/sodium.c
	gcc $(CFLAGS) -c -o $(BUILD)/sodium.o $(SRC)/sodium.c $(LFLAGS)

clean:
		rm -rf mesh_crypto $(BUILD)/*.o
