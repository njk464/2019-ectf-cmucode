#include <sodium.h>
#include <secret.h>
#include <mesh.h> 

#define MESH_CRYPTO_HEADER_ENTRY (crypto_secretbox_KEYBYTES + crypto_secretbox_NONCEBYTES*2 + crypto_secretbox_MACBYTES)

int verify_user_can_play(char *username, char* pin, char* gamepath);
void decrypt_game_file(char *username, char* pin, char* gamepath);
loff_t crypto_get_game_header(Game *game, char *game_name);
int crypto_get_game(char *game_binary, char *game_name, User* user);
