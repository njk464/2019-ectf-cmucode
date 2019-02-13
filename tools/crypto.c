#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define SALT_LEN 64

/*void encrypt_game(char* game_name, unsigned char *key_data){

    unsigned char salt[SALT_LEN] = read_salt();
    unsigned char key[KEY_LEN] = get_key();
    unsigned char nonce[NONCE_LEN] = get_nonce();
    unsigned char* ciphertext = read_in_game(game_name);
    
    if (sodium_init() < 0) {
        printf("Error in Crypto Library\n");
       	// Unsure if this is the correct way to terminate. 	
		exit(255);
    } else {
        memset(key, 0, sizeof(key));
		
        crypto_pwhash
            (key, sizeof key, key_data, strlen(key_data), salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_DEFAULT);

        memset(nonce, 0, sizeof(nonce));
        crypto_secretbox_easy(ciphertext, B->Buf, B->Length, nonce, key);
        free(B->Buf);
        B->Length = B->Length + crypto_secretbox_MACBYTES;
        B->Buf = malloc(B->Length);
        B->Buf = memcpy(B->Buf, ciphertext, B->Length);
    }
    return;
}

unsigned char* get_salt(){
    return 0;
}*/

unsigned int get_len(){
    FILE *fp;
    unsigned int len;
    fp = fopen("game.out", "r");     
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fclose(fp);
    return len;
}

void get_ciphertext(unsigned char *ptr, unsigned int len){
    FILE *fp;
    fp = fopen("game.out", "r");
    fread(ptr, 1, len, fp);
    //fgets(ptr, len+1, fp); 
    fclose(fp);
}

void get_key(unsigned char *ptr){
    FILE *fp;
    fp = fopen("key.out", "r");
    fread(ptr, 1, crypto_box_SEEDBYTES, fp);
    //fgets(ptr, crypto_box_SEEDBYTES, fp); 
    fclose(fp);
}

void get_nonce(unsigned char *ptr){
    FILE *fp;
    fp = fopen("nonce.out", "r");
    fread(ptr, 1, crypto_secretbox_NONCEBYTES, fp);
    //fgets(ptr, crypto_secretbox_NONCEBYTES, fp);
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

void decrypt_buffer(char* game_name, unsigned char *key_data){
    //unsigned char salt[]; get_salt();
    unsigned char key[crypto_box_SEEDBYTES];
    printf("SEEDBYTES: %d\n",crypto_box_SEEDBYTES);
    unsigned char nonce[crypto_secretbox_NONCEBYTES + 1];
    printf("NONCEBYES: %d\n",crypto_secretbox_NONCEBYTES);
    unsigned int len;
    len = get_len();
    unsigned int message_len = len - crypto_secretbox_MACBYTES;
    unsigned char ciphertext[len + 1];
    printf("len: %d\n", len);
	unsigned char plaintext[message_len];
    printf("message len: %d\n", message_len);

    if (sodium_init() < 0) {
        printf("Error in Crypto Library\n");
        exit(255);
    } else {
        memset(key, 0, sizeof(key));
        memset(nonce, 0, sizeof(nonce));
		memset(ciphertext, 0, sizeof(ciphertext));
        memset(plaintext, 0, sizeof(plaintext));
        get_ciphertext(ciphertext, len);
        get_key(key);
        get_nonce(nonce);
        if(game_name != 0) {
            printf("cipherText: ");
			print_hex(ciphertext, len);
            printf("nonce: ");
            print_hex(nonce, crypto_secretbox_NONCEBYTES);
            printf("key: ");
            print_hex(key, crypto_box_SEEDBYTES);
            if (crypto_secretbox_open(plaintext, ciphertext, len, nonce, key) == -1){
                printf("Message is: %s\n", plaintext);
                printf("integrity violation\n");
                exit(255);
            } else {
                printf("Message is: %s\n", plaintext);
            }
        }else{
            printf("Your Buf length is 0\n");
        }
    return;
    }
}

int main(){
    decrypt_buffer("game.out", "temp_key_data");
}
