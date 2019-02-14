#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define HEADER_LEN 16

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

void output_file(unsigned char *ptr, unsigned int len){
    FILE *fp;
    fp = fopen("test.out", "w");
    fwrite(ptr, 1, len, fp);
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
    unsigned char game_key[crypto_secretbox_KEYBYTES];
    unsigned char game_nonce[crypto_secretbox_NONCEBYTES];
    // This is the len of the entire file, signed.
    long long unsigned int file_len;
    file_len = get_len();
    // This is the len of the entire file, not signed. 
    long long unsigned int unsigned_file_len = file_len - crypto_sign_BYTES;
    // The is the unencrypted message length
    unsigned int unencrypted_file_len = unsigned_file_len - crypto_secretbox_MACBYTES - HEADER_LEN;
    unsigned char signed_file[file_len];
    unsigned char encrypted_game[unsigned_file_len];
    unsigned char file_pk[crypto_sign_PUBLICKEYBYTES];
    int i;
    if (sodium_init() < 0) {
        printf("Error in Crypto Library\n");
        exit(255);
    } else {
        //memset(game_key, 0, sizeof(game_key));
        //memset(game_nonce, 0, sizeof(game_nonce));
		//memset(ciphertext, 0, sizeof(ciphertext));
        //memset(pk, 0, sizeof(pk));
        // Read in the data from the files
        get_ciphertext(signed_file, file_len);
        get_key(game_key);
        get_nonce(game_nonce);
        get_pk(file_pk);
        if(game_name != 0) {
            if(crypto_sign_open(encrypted_game, &unsigned_file_len, signed_file, file_len, file_pk)==0){
                // get header
                unsigned char header[HEADER_LEN + 1];
                strncpy(header, encrypted_game, HEADER_LEN);
                header[HEADER_LEN] = '\0';
                printf("%s\n", header);

                // copy cipher text to itself-16
                for (i = 0; i < unsigned_file_len-HEADER_LEN; i++){
                        encrypted_game[i] = encrypted_game[i+HEADER_LEN];
                }
                
                // Pad the cipher text to send to the decrypt function
                unsigned int padded_len = crypto_secretbox_BOXZEROBYTES + unsigned_file_len - HEADER_LEN;
                unsigned char padded[padded_len];
                memset(padded, 0, sizeof(padded)); 
                int j = 0;
                for (i = 0; i < padded_len; i++){
                    if (i < crypto_secretbox_BOXZEROBYTES){
                        continue;
                    } else {
                        padded[i] = encrypted_game[j];
                        j++;
                    }
                }
                unsigned char plaintext[padded_len];
                // perform the decrypt
                if (crypto_secretbox_open(plaintext, padded, padded_len, game_nonce, game_key) == -1){
                    printf("integrity violation\n");
                    exit(255);
                } else {
                    unsigned char msg[padded_len];
                    // Move the data to print the string out.
                    // Remove the padding
                    for (i = 0; i < padded_len; i++){
                        msg[i] = plaintext[i + crypto_secretbox_BOXZEROBYTES * 2];
                        if (i > unencrypted_file_len){
                            break;
                        }
                    }

                    printf("The message is: |%s|\n", msg);
                    output_file(msg, unencrypted_file_len);
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
