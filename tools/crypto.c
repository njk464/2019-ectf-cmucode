#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define HEADER_LEN 16

unsigned int get_len(char *file_name){
    FILE *fp;
    unsigned int len;
    fp = fopen(file_name, "r");     
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fclose(fp);
    return len;
}

void *safe_calloc(size_t size){
    void *ptr;
    ptr = calloc(1, size);
    if (ptr){
        return ptr;
    }
    //Bad alloc
    exit(0);
}

void safe_free(void* ptr, size_t size){
    memset(ptr, 0, size);
    free(ptr);
    ptr = NULL;
}

void read_from_file(unsigned char *ptr, unsigned char *file_name, unsigned int len){
    FILE *fp;
    fp = fopen(file_name,"r");
    fread(ptr, 1, len, fp);
    fclose(fp);
}

void print_hex(unsigned char *ptr, unsigned int len) {
  	int i;
  	bool first = true;
    for (i = 0; i < len; i++) {
    	if(first) {
            printf("0x%02x", ptr[i]);
            first = false; 
        } else {
            printf(",0x%02x", ptr[i]);
  	    }
    }
  	printf("\n");
}

void gen_userkey(char *key, char* name, char* pin, char* game_name, char* version){
//#define MAX_USERNAME_LENGTH 15
//#define MAX_PIN_LENGTH 8
//#define MAX_GAME_LENGTH 31
//#define MAX_NUM_USERS 5
    //TODO: sketch
    int MAX_PASSWORD_SIZE = 15 + 8 + 31 + 5; 
    char password[MAX_PASSWORD_SIZE]; 
    char salt[crypto_pwhash_SALTBYTES];
    
    memset(key, 0, 32);
    sprintf(password, "%s%s%s%s", name, pin, game_name, version);
    // PASSWORD = name + pin + game_name + version
    read_from_file(salt, "salt.out", crypto_pwhash_SALTBYTES);
    if (crypto_pwhash(key, 32, password, strlen(password), salt, 
			crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN,
     		crypto_pwhash_ALG_DEFAULT) == 0) {
	} else {
		printf("Key Gen Failed\n");    
        exit(0);
	}
}

// Returns valud in message
void decrypt(char* key, char * nonce, char* message, unsigned int len, char* ret){
    int plaintext_len = len - crypto_secretbox_MACBYTES;
    int padded_len = len + crypto_secretbox_BOXZEROBYTES;
    unsigned char *padded_plaintext;
    unsigned char *padded_ciphertext;
    unsigned char *plaintext;
    
    padded_plaintext = safe_calloc(padded_len);
    padded_ciphertext = safe_calloc(padded_len);

    int j = 0;
    int i;
    for (i = 0; i < padded_len; i++){
        if (i < crypto_secretbox_BOXZEROBYTES){
            continue;
        } else {
            padded_ciphertext[i] = message[j];
            j++;
        }
    }

    if (crypto_secretbox_open(padded_plaintext, padded_ciphertext, padded_len, nonce, key) == -1){
        printf("Decrypt Fail\n");
        safe_free(padded_plaintext, padded_len);
        safe_free(padded_ciphertext, padded_len);
        exit(0);
    } else {
        plaintext = safe_calloc(plaintext_len);
        // Move the data to print the string out.
        // Remove the padding
        for (i = 0; i < plaintext_len; i++){
            plaintext[i] = padded_plaintext[i + crypto_secretbox_BOXZEROBYTES * 2];
            if (i > len){
                break;
            }
        }

        printf("The message is: |%s|\n", plaintext);
        memcpy(ret, plaintext, plaintext_len);
        safe_free(plaintext, plaintext_len);
        safe_free(padded_plaintext, padded_len);
        safe_free(padded_ciphertext, padded_len);
    }
}

//Assume that len is of signed_data
int verify_signed(unsigned char* signed_data, unsigned char* verified, unsigned long long int len, unsigned char* pk){
    unsigned long long int  verified_len = len - crypto_sign_BYTES;
    if(crypto_sign_open(verified, &verified_len, signed_data, len, pk) == 0){
        return 0;
    }else{
        printf("Signing Error\n");
        return -1;
    }
}

int main(){

    if (sodium_init() < 0) {
        printf("Error in Crypto Library\n");
        exit(0);
    }
    char user_key[32];
    gen_userkey(user_key,"user1", "12345678", "2048", "1.1");
    // read user nonce.
    char user_nonce[crypto_secretbox_NONCEBYTES];
    read_from_file(user_nonce, "user_nonce.out", crypto_secretbox_NONCEBYTES);
    // gamekey_nonce
    char pk[crypto_sign_PUBLICKEYBYTES];
    read_from_file(pk, "pk.out", crypto_sign_PUBLICKEYBYTES);
    /* main starts here*/
    unsigned long long int unverified_len = get_len("game.out");
    char *signed_ciphertext;
    signed_ciphertext = safe_calloc(unverified_len);
    read_from_file(signed_ciphertext, "game.out", unverified_len);
    
    unsigned long long int verified_len = unverified_len -  crypto_sign_BYTES;
    char *verified_ciphertext;
    verified_ciphertext = safe_calloc(verified_len);
    if(verify_signed(signed_ciphertext, verified_ciphertext, unverified_len, pk) == 0){    
        unsigned long long int encrypted_header_len; //length at beginning of file
        // TODO: verify that ull is the same size on Arty Z7
        memcpy(&encrypted_header_len, verified_ciphertext, sizeof(unsigned long long int));
        unsigned long long int decrypted_header_len = encrypted_header_len - crypto_secretbox_MACBYTES;
        unsigned long long int encrypted_game_len = verified_len - encrypted_header_len - sizeof(unsigned long long int);
        unsigned long long int decrypted_game_len = encrypted_game_len - crypto_secretbox_MACBYTES;
        // split header and game
        char *encrypted_header;
        encrypted_header = safe_calloc(encrypted_header_len);
        memcpy(encrypted_header, verified_ciphertext + sizeof(unsigned long long int), encrypted_header_len);
        // decrypt header to get gamekey/nonce
        char *gamekey_nonce;
        gamekey_nonce = safe_calloc(decrypted_header_len);
        decrypt(user_key, user_nonce, encrypted_header, encrypted_header_len, gamekey_nonce);
        char gamekey[crypto_secretbox_KEYBYTES];
        char gamenonce[crypto_secretbox_NONCEBYTES];
        memcpy(gamekey, gamekey_nonce, crypto_secretbox_KEYBYTES);
        memcpy(gamenonce, gamekey_nonce + crypto_secretbox_KEYBYTES, crypto_secretbox_NONCEBYTES);
    
        // decrypt game
        char *message;
        message = safe_calloc(decrypted_game_len);
        char *encrypted_game;
        encrypted_game = safe_calloc(encrypted_game_len);
        memcpy(encrypted_game, verified_ciphertext + sizeof(unsigned long long int) + encrypted_header_len, encrypted_game_len);
        decrypt(gamekey, gamenonce, encrypted_game, encrypted_game_len, message);
        printf("The message is %s\n", message);
        FILE *fp;
        fp = fopen("out.out", "w");
        fwrite(message, 1, decrypted_game_len, fp);
        fclose(fp);
        safe_free(encrypted_header, encrypted_header_len);
        safe_free(gamekey_nonce, decrypted_header_len);
        safe_free(message, decrypted_game_len);
        safe_free(encrypted_game, encrypted_game_len);
    } else {
        printf("Sign verify failed\n");
        // exit horribly
    }
    safe_free(signed_ciphertext, unverified_len);
    safe_free(verified_ciphertext, verified_len);
}
