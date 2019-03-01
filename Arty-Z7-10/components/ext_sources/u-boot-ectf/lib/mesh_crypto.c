#include <mesh_crypto.h>
#include <malloc.h>
#include <stdlib.h>

/*
 * @brief Given a username, read the salt from secret.h
 *
 * @params username The name of a user who salt is being returned
 * @return salt of specified user, NULL if user is not found. 
 */
char *get_salt(char *username){
    unsigned int i;
    for(i = 0; i < MAX_NUM_USERS; i++){
        if(strcmp(username, users[i]) == 0) {    
            return salt[i];
        }
    }
    return NULL;
}

/*
 * @brief Generate the userkey from supplied data
 *
 * @params key A pointer to the memory to place the key, already allocated
 * @params name The name of the user
 * @params pin The pin of the user
 * @params game_name The name of the game
 * @params version The version number of the game
 * @return void 
 */
void gen_userkey(char *key, char* name, char* pin, char* game_name, char* major_version, char* minor_version){
    int MAX_PASSWORD_SIZE = strlen(name) + strlen(pin) + strlen(game_name) + strlen(major_version) + strlen(minor_version) + crypto_pwhash_SALTBYTES + 1; 
    char password[MAX_PASSWORD_SIZE];
    memset(key, 0, crypto_hash_sha256_BYTES);
    // combine strings then memcpy non-standard characters from the salt
    if (sprintf(password, "%s%s%s%s.%s", name, pin, game_name, major_version, minor_version) < 0) {
        mesh_shutdown(NULL);
    }
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
 * @params ret A pointer to memory for decrypted data
 * @return int: 0 on success; else -1
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
    // add in padding necessary
    for (i = 0; i < padded_len; i++){
        if (i < crypto_secretbox_BOXZEROBYTES){
            continue;
        } else {
            padded_ciphertext[i] = message[j];
            j++;
        }
    }
    // decrypt the provided ciphertext
    if (crypto_secretbox_open(padded_plaintext, padded_ciphertext, padded_len, nonce, key) == -1){
        printf("Decrypt Fail\n");
        safe_free(padded_plaintext, padded_len);
        safe_free(padded_ciphertext, padded_len);
        return -1;
    } else {
        plaintext = safe_malloc(plaintext_len);
        // remove the padding
        for (i = 0; i < plaintext_len; i++){
            plaintext[i] = padded_plaintext[i + crypto_secretbox_BOXZEROBYTES * 2];
            if (i > len){
                break;
            }
        }
        // copy data to return location
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
    loff_t encrypted_header_len;
    loff_t decrypted_header_len;
    char *verified_ciphertext;
    char header_nonce[crypto_secretbox_NONCEBYTES];
    char *encrypted_header;
    char *original_decrypted_header;
    char *decrypted_header;
    char *game_version;
    char *parsed_game_name;
    char *end_game_name;
    char *start_name;
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
        // read in the size of the encrypted header. 
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

        // get the length of the game, which is the verified len - the all header data - MAC bytes
        decrypted_game_len = verified_len - encrypted_header_len - sizeof(unsigned long long int) - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;

        strsep(&decrypted_header,":");
        game_version = strsep(&decrypted_header,"\n");
        strsep(&decrypted_header,":");
        parsed_game_name = strsep(&decrypted_header,"\n");
        end_game_name = decrypted_header - 1; // This is -1 because I don't want to include the newline

        // get everything up to the first '.'. That's the major version
        char *temp_pointer = game_version;
        // get after the '.'. That's the minor version
        char* major_version_str = strsep(&temp_pointer, ".");
        char* minor_version_str = strsep(&temp_pointer, "\n");

        game->major_version = simple_strtoul(major_version_str, NULL, MAX_VERSION_LENGTH);
        game->minor_version = simple_strtoul(minor_version_str, NULL, MAX_VERSION_LENGTH);

        memcpy(game->name, parsed_game_name, end_game_name - parsed_game_name);
        game->name[end_game_name - parsed_game_name] = '\0';

        // compare the header to provided name
        char* full_name = (char*) safe_malloc(MAX_GAME_LENGTH + 1);
        if(snprintf(full_name, MAX_GAME_LENGTH + 1, "%s-v%d.%d", game->name, game->major_version, game->minor_version) <=0){
            printf("Game header data corrupted.");
            return -1;
        } 
        if (strncmp(full_name, game_name, MAX_GAME_LENGTH + 1) != 0){
            printf("Header data and file name do not match.");
            safe_free(full_name, MAX_GAME_LENGTH + 1);
            return -1;
        }
        safe_free(full_name, MAX_GAME_LENGTH + 1);
        
        start_name = decrypted_header; 
        // loop though the header
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
            // populate username into structure
            memset(game->users[num_users], 0, MAX_USERNAME_LENGTH);
            memcpy(game->users[num_users], start_name, end_name - start_name);
            game->users[num_users][end_name - start_name] = '\0';
            // move passed remainder of data in header
            decrypted_header += MESH_CRYPTO_HEADER_ENTRY; 
            start_name = decrypted_header;
            num_users++;
        }
        // store reaminder of data before exiting
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

/*
 * @brief This function returns the decrypted game binary for selected user.
 *
 * @params game_binary a pointer to return location for game_binary
 * @params game_name a string of the name of the game file
 * @params user user struct holding username and pin of the user
 * @return 1 on success, -1 on error. 
 */
int crypto_get_game(char *game_binary, char *game_name, User* user){
    int num_users = 0;
    int flag = 0;
    loff_t unverified_len;
    loff_t verified_len;
    loff_t decrypted_game_len;
    loff_t encrypted_header_len;
    loff_t decrypted_header_len;
    loff_t encrypted_game_len;
    loff_t encrypted_gamekeynonce_len;
    
    encrypted_gamekeynonce_len = crypto_secretbox_KEYBYTES + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;

    char header_nonce[crypto_secretbox_NONCEBYTES];
    char test_name[MAX_USERNAME_LENGTH];
    char user_key[crypto_secretbox_KEYBYTES];
    char user_nonce[crypto_secretbox_NONCEBYTES];
    char gamekey[crypto_secretbox_KEYBYTES];
    char gamenonce[crypto_secretbox_NONCEBYTES];
    char encrypted_gamekeynonce[encrypted_gamekeynonce_len];
    char gamekey_nonce[crypto_secretbox_NONCEBYTES + crypto_secretbox_KEYBYTES];
    char *verified_ciphertext;
    char *encrypted_header;
    char *original_decrypted_header;
    char *decrypted_header;
    char *game_version;
    char *parsed_game_name;
    char *end_game_name;
    char *start_name;
    char *enc_header_start;
    char *message;
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

        // get the length of the game, which is the verified len - the 
        decrypted_game_len = verified_len - encrypted_header_len - sizeof(unsigned long long int) - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;

        strsep(&decrypted_header,":");
        game_version = strsep(&decrypted_header,"\n");
        strsep(&decrypted_header,":");
        parsed_game_name = strsep(&decrypted_header,"\n");
        end_game_name = decrypted_header - 1; 

        // get everything up to the first '.'. That's the major version
        char *temp_pointer = game_version;
        // get after the '.'. That's the minor version
        char* major_version_str = strsep(&temp_pointer, ".");
        char* minor_version_str = strsep(&temp_pointer, "\n");

        int major_version = simple_strtoul(major_version_str, NULL, MAX_VERSION_LENGTH);
        int minor_version = simple_strtoul(minor_version_str, NULL, MAX_VERSION_LENGTH);

        char * name = safe_malloc((end_game_name - parsed_game_name)+1);
        memcpy(name, parsed_game_name, end_game_name - parsed_game_name);
        name[end_game_name - parsed_game_name] = '\0';

        // compare the header to provided name
        char* full_name = (char*) safe_malloc(MAX_GAME_LENGTH + 1);
        if(snprintf(full_name, MAX_GAME_LENGTH + 1, "%s-v%s.%s", name, major_version_str, minor_version_str) <=0){
            printf("Game header data corrupted.");
            return -1;
        } 
        if (strncmp(full_name, game_name, MAX_GAME_LENGTH + 1) != 0){
            printf("Header data and file name do not match.");
            safe_free(full_name, MAX_GAME_LENGTH + 1);
            return -1;
        }
        safe_free(full_name, MAX_GAME_LENGTH + 1);

        start_name = decrypted_header; 
        // loop though the header ensure extract encrypted game key + nonce
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
                decrypted_header += MESH_CRYPTO_HEADER_ENTRY; 
                start_name = decrypted_header;
            }
            num_users++;
        }
        // check for found user
        if(flag == 1){
            // get the user key
            gen_userkey(user_key, user->name, user->pin, parsed_game_name, major_version_str, minor_version_str);

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
