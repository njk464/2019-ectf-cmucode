#include <sodium.h>
#include <stdio.h>
#include <string.h>
/*
#include "libsodium.h"

#define crypto_pwhash_SALTBYTES 16U
#define crypto_pwhash_OPSLIMIT_MIN 1U
#define crypto_pwhash_MEMLIMIT_MIN 8192U
#define crypto_pwhash_ALG_DEFAULT 2U
#define crypto_secretbox_BOXZEROBYTES 16U
#define crypto_secretbox_NONCEBYTES 24U
#define crypto_secretbox_KEYBYTES 32U
#define crypto_sign_PUBLICKEYBYTES 32U
*/
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
      int first = 1;
    for (i = 0; i < len; i++) {
        if(first) {
            printf("0x%02x", ptr[i]);
            first = 0; 
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
// #define salt len 16    
//TODO: sketch
    int MAX_PASSWORD_SIZE = strlen(name) + strlen(pin) + strlen(game_name) + strlen(version) + crypto_pwhash_SALTBYTES ; 
    char password[MAX_PASSWORD_SIZE];
    char salt[crypto_pwhash_SALTBYTES]; 
    read_from_file(salt, "salt.out", crypto_pwhash_SALTBYTES);
    memset(key, 0, crypto_hash_sha256_BYTES);
    sprintf(password, "%s%s%s%s%s", name, pin, game_name, version, salt);
    // PASSWORD = name + pin + game_name + version
    int ret = crypto_hash_sha256(key, password, MAX_PASSWORD_SIZE);
    //printf("The key is: ");
    //print_hex(key, crypto_hash_sha256_BYTES);
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

int nick_test(){
    if (sodium_init() < 0) {
        printf("Error in Crypto Library\n");
        exit(0);
    }
    printf("Start\n");
    char game_key[crypto_secretbox_KEYBYTES];
    read_from_file(game_key, "key.out", crypto_secretbox_KEYBYTES);
    char game_nonce[crypto_secretbox_NONCEBYTES];
    read_from_file(game_nonce, "nonce.out", crypto_secretbox_NONCEBYTES);
    
    unsigned long long int len = get_len("nick.out");
    
    char *ciphertext;
    ciphertext = safe_calloc(len);
    printf("Read key and nonce\n");
    read_from_file(ciphertext, "nick.out", len);
    printf("Read from file\n");
    unsigned long long int decrypted_game_len = len - crypto_secretbox_MACBYTES;

    char *message;
    message = safe_calloc(decrypted_game_len);
    printf("Decrypt\n");
    decrypt(game_key, game_nonce, ciphertext, len, message);

    printf("Post decrypt\n");
    FILE *fp;
    fp = fopen("nick_dec.out", "w");
    fwrite(message, 1, decrypted_game_len, fp);
    fclose(fp);
    return 0;
}

int decrypt_test(){
    if (sodium_init() < 0) {
        printf("Error in Crypto Library\n");
        exit(0);
    }
    printf("Start\n");
    char game_key[crypto_secretbox_KEYBYTES];
    read_from_file(game_key, "key.out", crypto_secretbox_KEYBYTES);
    char game_nonce[crypto_secretbox_NONCEBYTES];
    read_from_file(game_nonce, "nonce.out", crypto_secretbox_NONCEBYTES);
    
    unsigned long long int len = get_len("nick.out");
    
    char *ciphertext;
    ciphertext = safe_calloc(len);
    // printf("Read key and nonce\n");
    read_from_file(ciphertext, "nick.out", len);
    // printf("Read from file\n");
    unsigned long long int decrypted_game_len = len - crypto_secretbox_MACBYTES;

    char *message;
    message = safe_calloc(decrypted_game_len);
    // printf("Decrypt\n");
    decrypt(game_key, game_nonce, ciphertext, len, message);

    // printf("Post decrypt\n");
    FILE *fp;
    fp = fopen("nick_dec.out", "w");
    fwrite(message, 1, decrypted_game_len, fp);
    fclose(fp);
    return 0;
}

int singed_basic_header_test(){
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
    return 1;
}

void gen_userkey_test(){
    if (sodium_init() < 0) {
        printf("Error in Crypto Library\n");
        exit(0);
    }
    char user_key[32];
    gen_userkey(user_key,"user1", "12345678", "2048", "1.1");
}

void full_decrypt_test(){
    // read in pulbic key, header key and nonce, salt for a user(the test user)
    // read in file
    // verify signature
    // get header size
    // split header and game
    // decrypt header
    // verify name, version
    // Get E(gamekey_nonce) and nonce for the specified user
    // decrypt gamekey nonce
    // split key and nonce
    // decrypt game
    // output game to a file
    char *user = "user";
    char *pin = "56781234";
    char *name = "2048";
    char *version = "1.1"; // Use 1.1, since the salt will get overwritten from 1.0
    char *signed_ciphertext;
    char user_key[crypto_secretbox_KEYBYTES];
    char user_nonce[crypto_secretbox_NONCEBYTES];
    char key[crypto_secretbox_KEYBYTES];
    char nonce[crypto_secretbox_NONCEBYTES];
    char pk[crypto_sign_PUBLICKEYBYTES]; 
    char gamekey[crypto_secretbox_KEYBYTES];
    char gamenonce[crypto_secretbox_NONCEBYTES];
    // These vaues are ONLY for this test game 2048
    char *game_name;
    char *game_version;
    // This will change is we stop using base64
    char *encoded_gamekeynonce;
    char *encoded_nonce;
    char *verified_ciphertext;
    char *encrypted_header;
    char *decrypted_header;
    unsigned long long int unverified_len;
    unsigned long long int verified_len;
    unsigned long long int encrypted_header_len;
    unsigned long long int decrypted_header_len;
    unsigned long long int encrypted_game_len;
    unsigned long long int decrypted_game_len;

    if (sodium_init() < 0) {
        printf("Error in Crypto Library\n");
        exit(0);
    }
    // This function reads the salt in from salt.out
    gen_userkey(user_key, user, pin, name, version);
    // read the key
    read_from_file(key, "key.out", crypto_secretbox_KEYBYTES);
    // read the nonce.
    read_from_file(nonce, "nonce.out", crypto_secretbox_NONCEBYTES);
    // read the public key
    read_from_file(pk, "pk.out", crypto_sign_PUBLICKEYBYTES);
    // Get the length of the file 
    unverified_len = get_len("2048-v1.1");
    // Read in the game file
    signed_ciphertext = safe_calloc(unverified_len);
    read_from_file(signed_ciphertext, "2048-v1.1", unverified_len);
    verified_len = unverified_len -  crypto_sign_BYTES;
    verified_ciphertext = safe_calloc(verified_len);
    // Check the signature
    if(verify_signed(signed_ciphertext, verified_ciphertext, unverified_len, pk) == 0){    
        // Read in the size of the encrypted header. 
        memcpy(&encrypted_header_len, verified_ciphertext, sizeof(unsigned long long int));
        decrypted_header_len = encrypted_header_len - crypto_secretbox_MACBYTES;
        encrypted_game_len = verified_len - encrypted_header_len - sizeof(unsigned long long int);
        decrypted_game_len = encrypted_game_len - crypto_secretbox_MACBYTES;
        // split header and game
        encrypted_header = safe_calloc(encrypted_header_len);
        memcpy(encrypted_header, verified_ciphertext + sizeof(unsigned long long int), encrypted_header_len);
        // decrypt header 
        decrypted_header = safe_calloc(decrypted_header_len); 
        decrypt(key, nonce, encrypted_header, encrypted_header_len, decrypted_header);
        strsep(&decrypted_header,":");
        game_version = strsep(&decrypted_header,"\n");
        strsep(&decrypted_header,":");
        game_name = strsep(&decrypted_header,"\n");

        printf("Version: %s\n", game_version);
        printf("Name: %s\n", game_name);
        // TODO: change to NOT use base64
        char *row;
        char *test_user;
        // This may read one too many and crash!!! 
        // TODO: fix this crash
        int flag = 0;
        while( (row = strsep(&decrypted_header,":")) != NULL ){
            printf("Row: %s\n", row);
            // read the first user
            test_user = strsep(&decrypted_header," ");
            printf("Test user: %s\n", test_user);
            if(strcmp(test_user, user) == 0){
                printf("Found the correct user\n");
                encoded_gamekeynonce = strsep(&decrypted_header, " ");
                encoded_nonce = strsep(&decrypted_header, "\n");
                printf("encoded gamekey nonce: %s\n", encoded_gamekeynonce);
                printf("encoded nonce: %s\n", encoded_nonce);
                flag = 1;
                break;
            } else {
                printf("Not correct user\n");
                // strsep to the end of the line
                strsep(&decrypted_header,"\n");
            }
        }
        if (flag == 0){
            printf("Not a valid user for this game!\n");
            return;
        }
        
        // All this BS is nessasary to covert from b'' format from python
        encoded_gamekeynonce += 2;
        encoded_nonce += 2;
        encoded_gamekeynonce[strlen(encoded_gamekeynonce) - 1] = '\0'; 
        encoded_nonce[strlen(encoded_nonce) - 1] = '\0'; 
        printf("encoded gamekey nonce: %s\n", encoded_gamekeynonce);
        printf("encoded nonce: %s\n", encoded_nonce);
        // int sodium_base642bin(unsigned char * const bin, const size_t bin_maxlen,
        //             const char * const b64, const size_t b64_len,
        //             const char * const ignore, size_t * const bin_len,
        //             const char ** const b64_end, const int variant); 
		size_t const encrypted_gamekeynonce_len = crypto_secretbox_KEYBYTES + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;		
        size_t const nonce_len = crypto_secretbox_NONCEBYTES;
        unsigned char encrypted_gamekeynonce[encrypted_gamekeynonce_len];
        size_t encoded_gamekeynonce_len = strlen(encoded_gamekeynonce);
        size_t encoded_nonce_len = strlen(encoded_nonce);

        sodium_base642bin(encrypted_gamekeynonce, sodium_base64_ENCODED_LEN(encrypted_gamekeynonce_len, sodium_base64_VARIANT_ORIGINAL),
						encoded_gamekeynonce, encoded_gamekeynonce_len,
						"", (size_t * const)&encrypted_gamekeynonce_len,
						NULL, sodium_base64_VARIANT_ORIGINAL);
		
        sodium_base642bin(user_nonce, sodium_base64_ENCODED_LEN(crypto_secretbox_NONCEBYTES, sodium_base64_VARIANT_ORIGINAL),
						encoded_nonce, encoded_nonce_len,
						"", (size_t * const)&nonce_len,
						NULL, sodium_base64_VARIANT_ORIGINAL);
        // END CHANGE AFTER BASE64 IS REMOVED

        char *gamekey_nonce;
        gamekey_nonce = safe_calloc(encrypted_gamekeynonce_len - crypto_secretbox_MACBYTES);
        // decrypt the gamekeynonce
        decrypt(user_key, user_nonce, encrypted_gamekeynonce, encrypted_gamekeynonce_len, gamekey_nonce);
        memcpy(gamekey, gamekey_nonce, crypto_secretbox_KEYBYTES);
        memcpy(gamenonce, gamekey_nonce + crypto_secretbox_KEYBYTES, crypto_secretbox_NONCEBYTES);
    
        // decrypt game
        char *message;
        message = safe_calloc(decrypted_game_len);
        char *encrypted_game;
        encrypted_game = safe_calloc(encrypted_game_len);
        memcpy(encrypted_game, verified_ciphertext + sizeof(unsigned long long int) + encrypted_header_len, encrypted_game_len);
        decrypt(gamekey, gamenonce, encrypted_game, encrypted_game_len, message);
        //printf("The message is %s\n", message);
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

int main(){
    // decrypt_test();
    // singed_basic_header_test();
    // gen_userkey_test();
    full_decrypt_test();
}
