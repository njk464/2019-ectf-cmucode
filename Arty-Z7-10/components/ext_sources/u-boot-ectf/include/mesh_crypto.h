//#include <sodium.h>
// #include <stdio.h>
// #include <string.h>
#include <sodium.h>
#include <secret.h>
#include <mesh.h> 

void *safe_malloc(size_t size);
void safe_free(void* ptr, size_t size);
int verify_user_can_play(char *username, char* pin, char* gamepath);
void decrypt_game_file(char *username, char* pin, char* gamepath);
loff_t crypto_get_game_header(Game *game, char *game_name);
int crypto_get_game(char *game_binary, char *game_name, User* user);
