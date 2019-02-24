//#include <sodium.h>
// #include <stdio.h>
// #include <string.h>
#include <sodium.h>
#include <secret.h>

void *safe_malloc(size_t size);
void safe_free(void* ptr, size_t size);
int verify_user_can_play(char *username, char* pin, char* gamepath);
void decrypt_game_file(char *username, char* pin, char* gamepath);
int crypto_get_game_header(Game *game, char *game_name);
