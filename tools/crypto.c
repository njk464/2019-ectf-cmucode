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
    fclose(fp);
}

void get_key(unsigned char *ptr){
    FILE *fp;
    fp = fopen("key.out", "r");
    fread(ptr, 1, crypto_secretbox_KEYBYTES, fp);
    fclose(fp);
}

void get_nonce(unsigned char *ptr){
    FILE *fp;
    fp = fopen("nonce.out", "r");
    fread(ptr, 1, crypto_secretbox_NONCEBYTES, fp);
    fclose(fp);
}

void output_file(unsigned char *ptr, int message_len){
    FILE *fp;
    fp = fopen("test.out", "w");
    fwrite(ptr, 1, message_len, fp);
    fclose(fp);
}

void get_pk(unsigned char *ptr){
    FILE *fp;
    fp = fopen("pk.out", "r");
    fread(ptr, 1, crypto_sign_PUBLICKEYBYTES, fp);
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
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    long long unsigned int len;
    len = get_len();
    long long unsigned int verified_len = len - crypto_sign_BYTES;
    unsigned int message_len = verified_len - crypto_secretbox_MACBYTES;
    unsigned char unverified[len];
    unsigned char ciphertext[verified_len];
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];

    if (sodium_init() < 0) {
        printf("Error in Crypto Library\n");
        exit(255);
    } else {
        memset(key, 0, sizeof(key));
        memset(nonce, 0, sizeof(nonce));
		memset(ciphertext, 0, sizeof(ciphertext));
        memset(pk, 0, sizeof(pk));
        // Read in the data from the files
        get_ciphertext(unverified, len);
        get_key(key);
        get_nonce(nonce);
        get_pk(pk);
        if(game_name != 0) {
            printf("Before check\n");
            if(crypto_sign_open(ciphertext, &verified_len, unverified, len, pk)==0){
                // get header
                unsigned char header[16];
                strncpy(header, ciphertext, 16);
                header[16] = '\0';
                printf("%s\n", header);
                *ciphertext += 15;
                
                // Pad the cipher text to send to the decrypt function
                unsigned int padded_len = crypto_secretbox_BOXZEROBYTES + verified_len;
                unsigned char padded[padded_len];
                memset(padded, 0, sizeof(padded)); 
                int j = 0;
                for (int i = 0; i < padded_len; i++){
                    if (i < crypto_secretbox_BOXZEROBYTES){
                        continue;
                    } else {
                        padded[i] = ciphertext[j];
                        j++;
                    }
                }
                unsigned char plaintext[padded_len];
                // perform the decrypt
                if (crypto_secretbox_open(plaintext, padded, padded_len, nonce, key) == -1){
                    printf("integrity violation\n");
                    exit(255);
                } else {
                    unsigned char msg[padded_len];
                    // Move the data to print the string out.
                    // Remove the padding
                    for (int i = 0; i < padded_len; i++){
                        msg[i] = plaintext[i + crypto_secretbox_BOXZEROBYTES * 2];
                        if (i > len){
                            break;
                        }
                    }

                    printf("The message is: |%s|\n", msg);
                    output_file(msg, message_len);
                }
            }
        } else {
            printf("Your Buf length is 0\n");
        }
    return;
    }
}

int main(){
    decrypt_buffer("game.out", "temp_key_data");
}
