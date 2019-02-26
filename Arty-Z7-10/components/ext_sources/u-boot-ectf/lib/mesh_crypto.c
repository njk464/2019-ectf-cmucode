#include <mesh_crypto.h>
#include <malloc.h>
#include <stdlib.h>


/*
 * @brief Clears memory before freeing
 *
 * @params ptr A pointer to the memory to free
 * @params size The size of the memory to be freed
 * @return Void
 */
void safe_free(void* ptr, size_t size){
    memset(ptr, 0, size);
    free(ptr);
    ptr = NULL;
}

/*
 * @brief TODO: This is a debug function
 *              It prints out memory in hex for easy debugging
 * @params ptr A pointer to the data
 * @params len The len of the data
 * @return void
 */
void print_hex(unsigned char *ptr, unsigned int len) {
    int i;
    int first = 1;
    for (i = 0; i <= len; i++) {
        if(first) {
            printf("0x%02x", ptr[i]);
            first = 0; 
        } else {
            printf(",0x%02x", ptr[i]);
        }
    }
    printf("\n");
}

/*
 * @brief Given a username, read the salt from secret.h
 *
 * @params username The name of a user who salt is being returned
 * @return NULL if this is an invalid user, the salt otherwise. 
 */
char *get_salt(char *username){
    unsigned int i;
    for(i = 0; i < MAX_NUM_USERS; i++){
        if(strcmp(username, users[i]) == 0) {    
            return salt[i];
        }
    }
    printf("Salt not found\n");
    return NULL;
}

/*
 * @brief Generate the userkey from supplied data
 *
 * @params key A pointer to the location in memory to place the key
 * @params name The name of the user
 * @params pin The pin of the user
 * @params game_name The name of the game
 * @params version The version number of the game
 * @return void 
 */
void gen_userkey(char *key, char* name, char* pin, char* game_name, char* version){
    int MAX_PASSWORD_SIZE = strlen(name) + strlen(pin) + strlen(game_name) + strlen(version) + crypto_pwhash_SALTBYTES ; 
    char password[MAX_PASSWORD_SIZE];
    memset(key, 0, crypto_hash_sha256_BYTES);
    sprintf(password, "%s%s%s%s", name, pin, game_name, version);
    memcpy(password + MAX_PASSWORD_SIZE - crypto_pwhash_SALTBYTES, get_salt(name), crypto_pwhash_SALTBYTES);
    crypto_hash_sha256((unsigned char*) key, 
                                 (const unsigned char *) password, 
                                 (unsigned long long) MAX_PASSWORD_SIZE);
    return;
}

/*
 * @brief Performs a decrypt on the data.
 * 
 * @params key The key for use in decryption
 * @params nonce The nonce for use in decryption
 * @params message The message to decrypt
 * @params len The len of the encrypted message
 * @params ret A pointer to the location in memory of the decrypted data
 * @return int: return 0 on success; else -1
 */
int decrypt(char* key, char* nonce, char* message, unsigned int len, char* ret){
    int plaintext_len = len - crypto_secretbox_MACBYTES;
    int padded_len = len + crypto_secretbox_BOXZEROBYTES;
    unsigned char *padded_plaintext;
    unsigned char *padded_ciphertext;
    unsigned char *plaintext;
    
    padded_plaintext = safe_malloc(padded_len);
    padded_ciphertext = safe_malloc(padded_len);

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
        // exit(0);
        return -1;
    } else {
        plaintext = safe_malloc(plaintext_len);
        // Move the data to print the string out.
        // Remove the padding
        for (i = 0; i < plaintext_len; i++){
            plaintext[i] = padded_plaintext[i + crypto_secretbox_BOXZEROBYTES * 2];
            if (i > len){
                break;
            }
        }

        //printf("The message is: |%s|\n", plaintext);
        memcpy(ret, plaintext, plaintext_len);
        safe_free(plaintext, plaintext_len);
        safe_free(padded_plaintext, padded_len);
        safe_free(padded_ciphertext, padded_len);
        return 0;
    }
}

/*
 * @brief Performs signature verification
 *
 * @params signed_data A pointer to the signed data
 * @params verified A pointer to the memory that the unsigned data will be stored
 * @params len The len of the signed data
 * @params pk The public key that is used
 * @return -1 on Error, 0 otherwise. 
 */
int verify_signed(unsigned char* signed_data, unsigned char* verified, unsigned long long int len, unsigned char* pk){
    unsigned long long int  verified_len = len - crypto_sign_BYTES;
    if(crypto_sign_open(verified, &verified_len, signed_data, len, pk) == 0){
        return 0;
    }else{
        printf("Signing Error\n");
        return -1;
    }
}


/*
 * @brief This function extract the game info from the header of a game file.
 *
 * @params game A pointer to a Game struct that will be populated with the game data 
 * @params game_name The name of the game that we are getting the header info from
 * @return The size of the game unencrypted game binary, -1 on error. 
 */
loff_t crypto_get_game_header(Game *game, char *game_name){
    int num_users = 0;
    loff_t unverified_len;
    loff_t verified_len;
    loff_t decrypted_game_len;
    char *verified_ciphertext;
    loff_t encrypted_header_len;
    loff_t decrypted_header_len;
    char *encrypted_header;
    char header_nonce[crypto_secretbox_NONCEBYTES];
    char *original_decrypted_header;
    char *decrypted_header;
    char *game_version;
    char *parsed_game_name;
    char *end_game_name;
    char *start_name;
    char test_name[MAX_USERNAME_LENGTH];
    char *signed_ciphertext;

    if (sodium_init() < 0) {
        printf("Error in Crypto Library\n");
        return -1;
    }
    
    // get the size of the game
    unverified_len = mesh_size_ext4(game_name);
    verified_len = unverified_len -  crypto_sign_BYTES;
    verified_ciphertext = safe_malloc(verified_len);

    // read the game into a buffer
    signed_ciphertext = (char*) safe_malloc(unverified_len); //TODO: Check length (+1)
    mesh_read_ext4(game_name, signed_ciphertext, unverified_len);

    if(verify_signed(signed_ciphertext, verified_ciphertext, unverified_len, sign_public_key) == 0){
        // Read in the size of the encrypted header. 
        memcpy(&encrypted_header_len, verified_ciphertext, sizeof(unsigned long long int));
        decrypted_header_len = encrypted_header_len - crypto_secretbox_MACBYTES;
        // read in header_nonce
        memcpy(header_nonce, verified_ciphertext + sizeof(unsigned long long int), crypto_secretbox_NONCEBYTES);
        // read only the header
        encrypted_header = safe_malloc(encrypted_header_len);
        memcpy(encrypted_header, verified_ciphertext + sizeof(unsigned long long int) + crypto_secretbox_NONCEBYTES, encrypted_header_len);
        // decrypt header 
        decrypted_header = safe_malloc(decrypted_header_len); 
        original_decrypted_header = decrypted_header;
        decrypt(header_key, header_nonce, encrypted_header, encrypted_header_len, decrypted_header);

        // Get the length of the game, which is the verified len - the 
        decrypted_game_len = verified_len - encrypted_header_len - sizeof(unsigned long long int) - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;

        strsep(&decrypted_header,":");
        game_version = strsep(&decrypted_header,"\n");
        strsep(&decrypted_header,":");
        parsed_game_name = strsep(&decrypted_header,"\n");
        end_game_name = decrypted_header - 2; // This is -2 because I don't want to include the newline

        // get everything up to the first '.'. That's the major version
        char *temp_pointer = game_version;
        // get after the '.'. That's the minor version
        char* major_version_str = strsep(&temp_pointer, ".");
        char* minor_version_str = strsep(&temp_pointer, "\n");

        game->major_version = simple_strtoul(major_version_str, NULL, 10);
        game->minor_version = simple_strtoul(minor_version_str, NULL, 10);

        memcpy(game->name, parsed_game_name, end_game_name - parsed_game_name);
        game->name[end_game_name - parsed_game_name] = '\0';

        start_name = decrypted_header; 
        // Loop though the header
        while((decrypted_header = strstr(decrypted_header," ")) != NULL ){
            if(num_users > MAX_NUM_USERS) {
                printf("Max users reached\n");
                safe_free(encrypted_header, encrypted_header_len);
                safe_free(original_decrypted_header, decrypted_header_len);
                safe_free(verified_ciphertext, verified_len);
                safe_free(signed_ciphertext, unverified_len);
                return -1;
            }
            char* end_name = decrypted_header; 
            decrypted_header++; // bypass space
            memset(test_name, 0, MAX_USERNAME_LENGTH);
            memcpy(test_name, start_name, end_name - start_name);
            memcpy(game->users[num_users], test_name, end_name - start_name);
            game->users[num_users][end_name - start_name] = '\0';
            decrypted_header += 96; 
            start_name = decrypted_header;
            num_users++;
        }
        game->num_users = num_users;
        safe_free(encrypted_header, encrypted_header_len);
        safe_free(original_decrypted_header, decrypted_header_len);
    } else {
        printf("Sign check fail\n");
        safe_free(verified_ciphertext, verified_len);
        safe_free(signed_ciphertext, unverified_len);
        return -1;
    }
    safe_free(verified_ciphertext, verified_len);
    safe_free(signed_ciphertext, unverified_len);
    return decrypted_game_len;
}

int crypto_get_game(char *game_binary, char *game_name, User* user){
    int num_users = 0;
    loff_t unverified_len;
    loff_t verified_len;
    loff_t decrypted_game_len;
    char *verified_ciphertext;
    loff_t encrypted_header_len;
    loff_t decrypted_header_len;
    char *encrypted_header;
    char header_nonce[crypto_secretbox_NONCEBYTES];
    char *original_decrypted_header;
    char *decrypted_header;
    char *game_version;
    char *parsed_game_name;
    char *end_game_name;
    char *start_name;
    char test_name[MAX_USERNAME_LENGTH];
    loff_t encrypted_game_len;
    loff_t encrypted_gamekeynonce_len;
    encrypted_gamekeynonce_len = crypto_secretbox_KEYBYTES + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
    char *enc_header_start;
    char user_key[crypto_secretbox_KEYBYTES];
    char user_nonce[crypto_secretbox_NONCEBYTES];
    char gamekey[crypto_secretbox_KEYBYTES];
    char gamenonce[crypto_secretbox_NONCEBYTES];
    char encrypted_gamekeynonce[encrypted_gamekeynonce_len];
    char gamekey_nonce[crypto_secretbox_NONCEBYTES + crypto_secretbox_KEYBYTES];
    char *message;
    int flag = 0;
    char *encrypted_game;
    char *signed_ciphertext;

    if (sodium_init() < 0) {
        printf("Error in Crypto Library\n");
        return -1;
    }
    
    // get the size of the game
    unverified_len = mesh_size_ext4(game_name);
    verified_len = unverified_len -  crypto_sign_BYTES;
    verified_ciphertext = safe_malloc(verified_len);

    // read the game into a buffer
    signed_ciphertext = (char*) safe_malloc(unverified_len); //TODO: Check length (+1)
    mesh_read_ext4(game_name, signed_ciphertext, unverified_len);

    if(verify_signed(signed_ciphertext, verified_ciphertext, unverified_len, sign_public_key) == 0){
        // Read in the size of the encrypted header. 
        memcpy(&encrypted_header_len, verified_ciphertext, sizeof(unsigned long long int));
        decrypted_header_len = encrypted_header_len - crypto_secretbox_MACBYTES;
        encrypted_game_len = verified_len - encrypted_header_len - sizeof(unsigned long long int) - crypto_secretbox_NONCEBYTES;
        decrypted_game_len = encrypted_game_len - crypto_secretbox_MACBYTES;
        // read in header_nonce
        memcpy(header_nonce, verified_ciphertext + sizeof(unsigned long long int), crypto_secretbox_NONCEBYTES);
        
        enc_header_start = verified_ciphertext + sizeof(unsigned long long int) + crypto_secretbox_NONCEBYTES;
        // split header and game
        encrypted_header = safe_malloc(encrypted_header_len);
        memcpy(encrypted_header, enc_header_start, encrypted_header_len);
        // decrypt header 
        decrypted_header = safe_malloc(decrypted_header_len); 
        original_decrypted_header = decrypted_header;
        if(decrypt(header_key, header_nonce, encrypted_header, encrypted_header_len, decrypted_header) == -1){
            safe_free(encrypted_header, encrypted_header_len);
            safe_free(original_decrypted_header, decrypted_header_len);
            safe_free(verified_ciphertext, verified_len);
            safe_free(signed_ciphertext, unverified_len);
            return -1;
        }

        // Get the length of the game, which is the verified len - the 
        decrypted_game_len = verified_len - encrypted_header_len - sizeof(unsigned long long int) - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;

        strsep(&decrypted_header,":");
        game_version = strsep(&decrypted_header,"\n");
        strsep(&decrypted_header,":");
        parsed_game_name = strsep(&decrypted_header,"\n");
        end_game_name = decrypted_header - 2; // This is -2 because I don't want to include the newline

        start_name = decrypted_header; 
        // Loop though the header
        while((decrypted_header = strstr(decrypted_header," ")) != NULL ){
            if(num_users > MAX_NUM_USERS) {
                printf("Max users reached\n");
                safe_free(encrypted_header, encrypted_header_len);
                safe_free(original_decrypted_header, decrypted_header_len);
                safe_free(verified_ciphertext, verified_len);
                safe_free(signed_ciphertext, unverified_len);
                return -1;
            }
            char* end_name = decrypted_header; 
            decrypted_header++; // bypass space
            memset(test_name, 0, MAX_USERNAME_LENGTH);
            memcpy(test_name, start_name, end_name - start_name);
            if(strcmp(test_name, user->name) == 0){
                memcpy(encrypted_gamekeynonce, decrypted_header, encrypted_gamekeynonce_len);
                memcpy(user_nonce, decrypted_header + encrypted_gamekeynonce_len, crypto_secretbox_NONCEBYTES);
                flag = 1;
                break;
            } else {
                decrypted_header += 96; 
                start_name = decrypted_header;
            }
            num_users++;
        }
        if(flag == 1){
            // Get the user key
            gen_userkey(user_key, user->name, user->pin, parsed_game_name, game_version);

             // decrypt the gamekeynonce
            if(decrypt(user_key, user_nonce, encrypted_gamekeynonce, encrypted_gamekeynonce_len, gamekey_nonce) == -1){
                safe_free(encrypted_header, encrypted_header_len);
                safe_free(original_decrypted_header, decrypted_header_len);
                safe_free(verified_ciphertext, verified_len);
                safe_free(signed_ciphertext, unverified_len);
                return -1;
            }
            memcpy(gamekey, gamekey_nonce, crypto_secretbox_KEYBYTES);
            memcpy(gamenonce, gamekey_nonce + crypto_secretbox_KEYBYTES, crypto_secretbox_NONCEBYTES);
        
            // decrypt game
            // message = safe_malloc(decrypted_game_len);
            encrypted_game = safe_malloc(encrypted_game_len);
            memcpy(encrypted_game, enc_header_start + encrypted_header_len, encrypted_game_len);
            // decrypt and store the game. 
            if(decrypt(gamekey, gamenonce, encrypted_game, encrypted_game_len, game_binary) == -1){ 
                safe_free(encrypted_header, encrypted_header_len);
                safe_free(original_decrypted_header, decrypted_header_len);
                safe_free(encrypted_game, encrypted_game_len);
                safe_free(verified_ciphertext, verified_len);
                safe_free(signed_ciphertext, unverified_len);
                return -1;
            }
            safe_free(encrypted_header, encrypted_header_len);
            safe_free(original_decrypted_header, decrypted_header_len);
            safe_free(encrypted_game, encrypted_game_len);
        }else{
            printf("User cannot play game.\n");
            safe_free(signed_ciphertext, unverified_len);
            safe_free(verified_ciphertext, verified_len);
            return -1;
        }
    } else {
        printf("Sign check fail\n");
        safe_free(verified_ciphertext, verified_len);
        safe_free(signed_ciphertext, unverified_len);
        return -1;
    }
    safe_free(signed_ciphertext, unverified_len);
    safe_free(verified_ciphertext, verified_len);
    return 1; // good return
}
