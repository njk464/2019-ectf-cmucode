#ifndef __MESH_H__
#define __MESH_H__

#include <common.h>
#include <ext4fs.h>

#define MAX_STR_LEN 64
#define MAX_USERNAME_LENGTH 15
#define MAX_PIN_LENGTH 8
#define MAX_GAME_LENGTH 31
#define MAX_INT_STR_LENGTH 11
#define MAX_VERSION_LENGTH MAX_INT_STR_LENGTH
#define BASE 10
#define MAX_NUM_USERS 32
#define MAX_GAMES 128

#define MESH_SENTINEL_LOCATION 0x00000040
#define MESH_SENTINEL_VALUE 0xDEADBEEF
#define MESH_SENTINEL_LENGTH 4
#define MESH_INSTALL_GAME_OFFSET 0x00000044

#define MESH_TABLE_UNINSTALLED 0x00
#define MESH_TABLE_INSTALLED 0x01

#define MAX_LOGIN_ATTEMPTS 2
#define LOGIN_TIMEOUT 5000 // 5-seconds
#define MAX_GAMES_INSTALLED MAX_GAMES*MAX_NUM_USERS

// To erase (or call update) on flash, it needs to be done
// on boundaries of size 64K
#define FLASH_PAGE_SIZE 65536

#define MESH_TOK_BUFSIZE 64
#define MESH_TOK_DELIM " \t\r\n\a"
#define MESH_RL_BUFSIZE 1024
#define MESH_SHUTDOWN -2

// INSTALL ERROR CODES
#define INSTALL_INVALID_LENGTH 2
#define INSTALL_NO_GAME_EXISTS 3
#define INSTALL_USER_NOT_ALLOWED 4
#define INSTALL_DOWNGRADE 5
#define INSTALL_INSTALLED 6
#define INSTALL_LIMIT_REACHED 7
#define INSTALL_INVALID_SIGNATURE 8
#define INSTALL_UNKNOWN_ERROR -1

/**
 * @brief struct used to store the username and pin
 */
typedef struct {
    char name[MAX_USERNAME_LENGTH + 1];
    char pin[MAX_PIN_LENGTH + 1];
} User;

/**
 * @brief struct used to store game information
 *        after reading a game header
 */
typedef struct game {
    char name[MAX_GAME_LENGTH + 1];
    unsigned int major_version;
    unsigned int minor_version;
    char users[MAX_NUM_USERS][MAX_USERNAME_LENGTH + 1];
    int num_users;
} Game;

/**
 * @brief struct used to represent an installed game table entry
 */
struct games_tbl_row {
    char install_flag; // 00 no longer installed, 01 installed
    char game_name[MAX_GAME_LENGTH + 1];
    unsigned int major_version;
    unsigned int minor_version;
    char user_name[MAX_USERNAME_LENGTH + 1];
};

/*
    Helper functions
*/
int mesh_game_installed(char *game_name);
int mesh_play_validate_args(char **args);
int mesh_game_exists(char *game_name);
int mesh_check_downgrade(char *game_name, unsigned int major_version, unsigned int minor_version);
int mesh_check_user(Game *game);
void mesh_get_game_header(Game *game, char *game_name);
int mesh_install_validate_args(char **args);
int mesh_execute(char **args);
int mesh_is_first_table_write(void);
int mesh_validate_user(User *user);
int mesh_num_builtins(void) ;
char* mesh_read_line(int bufsize);
int mesh_get_argv(char **args);
char **mesh_split_line(char *line) ;
char* mesh_input(char* prompt);
int mesh_valid_install(char *game_name);
void ptr_to_string(void* ptr, char* buf);
void full_name_from_short_name(char* full_name, struct games_tbl_row* row);
void *safe_malloc(size_t size);
void *safe_calloc(size_t nitems, size_t size);
void *safe_realloc(void *ptr, size_t size);
void safe_free(void** ptr, size_t size);
void mesh_get_install_table(void);
void mesh_write_install_table(void);

/*
    Ext 4 functions
*/
int mesh_ls_ext4(const char *dirname, char *filename);
int mesh_ls_iterate_dir(struct ext2fs_node *dir, char *fname);
int mesh_query_ext4(const char *dirname, char *filename);
loff_t mesh_size_ext4(char *fname);
loff_t mesh_read_ext4(char *fname, char*buf, loff_t size);

/*
    Function Declarations for builtin shell commands:
 */

int mesh_help(char **args);
int mesh_shutdown(char **args);
int mesh_logout(char **args);
int mesh_list(char **args);
int mesh_play(char **args);
int mesh_query(char **args);
int mesh_install(char **args);
int mesh_uninstall(char **args);
int mesh_login(User *user) ;
void mesh_loop(void);

/*
 * Mesh flash commands
 */
int mesh_flash_init(void);
int mesh_flash_write(void* data, unsigned int flash_location, unsigned int flash_length);
int mesh_flash_read(void* data, unsigned int flash_location, unsigned int flash_length);
int mesh_is_first_table_write(void);

#endif
