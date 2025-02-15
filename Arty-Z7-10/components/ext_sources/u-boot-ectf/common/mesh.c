#include <common.h>
#include <cli.h>
#include <stdlib.h>
#include <ext_common.h>
#include <ext4fs.h>
#include "../fs/ext4/ext4_common.h"
#include <fs.h>
#include <spi.h>
#include <spi_flash.h>
#include <command.h>
#include <os.h>

#include <mesh.h>
#include <mesh_users.h>
#include <secret.h>
#include <default_games.h>
#include <bcrypt.h>
#include <mesh_crypto.h>

#define FLASH_CRYPTO_PAGE_SIZE (FLASH_PAGE_SIZE - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES - crypto_secretbox_BOXZEROBYTES)


/**
 * @brief handles the current logged in user information
 */
User user;
/**
 * @brief Saved installed games table in RAM
 */
struct games_tbl_row *installed_games;
/**
 * @brief Number of installed games
 */
unsigned int installed_games_size = 0;


/**
 * @brief List of builtin commands, followed by their corresponding functions.
 */
char *builtin_str[] = {
    "help",
    "shutdown",
    "logout",
    "list",
    "play",
    "query",
    "install",
    "uninstall"
};

int (*builtin_func[]) (char **) = {
    &mesh_help,
    &mesh_shutdown,
    &mesh_logout,
    &mesh_list,
    &mesh_play,
    &mesh_query,
    &mesh_install,
    &mesh_uninstall
};

static void random_nonce(char* buf);

/******************************************************************************/
/********************************** Flash Commands ****************************/
/******************************************************************************/

/**
 * @brief This function initializes the game install table. If the the sentinel is 
 *        written already, then, it does nothing, otherwise, it writes the sentinel 
 *        and a size of 0 at the beginning of the install table
 * @return 0 on success. !0 on failure
 */
int mesh_init_table(void)
{
    /* Initialize the table where games will be installed */
    char* sentinel = (char*) safe_malloc(sizeof(char) * MESH_SENTINEL_LENGTH);
    int ret = -1;

    ret = mesh_flash_read(sentinel, MESH_SENTINEL_LOCATION, MESH_SENTINEL_LENGTH);
    if (ret || *((unsigned int*) sentinel) != MESH_SENTINEL_VALUE)
    {
        installed_games_size = 0;
        mesh_write_install_table();
        ret = 0;
    }
    safe_free(&sentinel, sizeof(char) * MESH_SENTINEL_LENGTH);
    return ret;
}


/**
 * @brief This function initialized the flash memory for the Arty Z7. This must be done
 *        before executing any flash memory commands.
 */
int mesh_flash_init(void)
{
    char* probe_cmd[] = {"sf", "probe", "0", "2000000", "0"};
    cmd_tbl_t* sf_tp = find_cmd("sf");
    return sf_tp->cmd(sf_tp, 0, 5, probe_cmd);
}


/**
 * @brief This function reads a full page fom flash and stores the 
 * 
 * @param data buffer to read flash data to with size=FLASH_PAGE_SIZE
 * @param page the flash page number to read from
 * @return 0 on success. !0 on failure.
 */
int mesh_flash_read_page(void* data, unsigned int page)
{
    // Find the sf sub command
    cmd_tbl_t* sf_tp = find_cmd("sf");

    // We need to convert things to strings since this mimics the command prompt,
    // so get us space for strings
    char str_ptr[MAX_INT_STR_LENGTH] = "";
    char offset_ptr[MAX_INT_STR_LENGTH] = "";
    char length_ptr[MAX_INT_STR_LENGTH] = "";
    // Convert the point to a string representation
    ptr_to_string(data, str_ptr);
    ptr_to_string((unsigned int *) (page * FLASH_PAGE_SIZE), offset_ptr);
    ptr_to_string((unsigned int *) FLASH_PAGE_SIZE, length_ptr);

    // Perform an update
    char* read_cmd[] = {"sf", "read", str_ptr, offset_ptr, length_ptr};
    return sf_tp->cmd(sf_tp, 0, 5, read_cmd);
}


/**
 * @brief This functions the writes the data to the specified flash page. The data 
 *        should be page aligned.
 * 
 * @param data pointer to a buffer with size=FLASH_PAGE_SIZE
 * @param page page # that needs to be updated
 */
void mesh_flash_write_page(void* data, unsigned int page)
{
    // Find the sf sub command, defined by u-boot
    cmd_tbl_t* sf_tp = find_cmd("sf");

    // We need to convert things to strings since this mimics the command prompt
    char data_ptr_str[MAX_INT_STR_LENGTH] = "";
    char offset_str[MAX_INT_STR_LENGTH] = "";
    char length_str[MAX_INT_STR_LENGTH] = "";

    // Convert the pointer to a string representation (0xffffffff)
    ptr_to_string(data, data_ptr_str);
    ptr_to_string((void *) (page * FLASH_PAGE_SIZE), offset_str);
    ptr_to_string((void *) FLASH_PAGE_SIZE, length_str);

    // Perform an update on this page
    char* write_cmd[] = {"sf", "update", data_ptr_str, offset_str, length_str};
    sf_tp->cmd(sf_tp, 0, 5, write_cmd);
}


/**
 * @brief Writes flash_length bytes of encrypted data to flash_location in flash.
 *        The first 56 bytes of each page are reserved for the NONCE and MAC
 * 
 * @param data pointer to a buffer with size=flash_length
 * @param flash_location location to write to in flash
 * @param flash_length number of bytes to write
 * @return 0 on success. !0 on failure
 */
int mesh_flash_write(void* data, unsigned int flash_location, unsigned int flash_length)
{
    if (flash_length < 1)
        return 0;

    // malloc space to hold an entire page
    char* cipher_text = safe_calloc(1, FLASH_PAGE_SIZE);
    char* plain_text  = safe_calloc(1, FLASH_PAGE_SIZE - crypto_secretbox_NONCEBYTES);

    unsigned int new_offset = flash_location;

    while (new_offset - flash_location < flash_length) {

        unsigned int page = new_offset / FLASH_CRYPTO_PAGE_SIZE;
        unsigned int current_offset = new_offset % (FLASH_CRYPTO_PAGE_SIZE);
        unsigned int end_offset = FLASH_CRYPTO_PAGE_SIZE;
       
        if (flash_location + flash_length - new_offset + current_offset < end_offset) 
        {
            end_offset = flash_location + flash_length - new_offset + current_offset;
        }

        // copy data into plain text buffer
        memcpy(&plain_text[crypto_secretbox_ZEROBYTES] + current_offset, data, end_offset - current_offset);

        random_nonce(cipher_text);
        // memset(cipher_text, 0, crypto_secretbox_NONCEBYTES);
        memset(plain_text, 0, crypto_secretbox_ZEROBYTES);

        // encrypt the data
        if((crypto_secretbox( (unsigned char*)  &cipher_text[crypto_secretbox_NONCEBYTES],
                              (const unsigned char*)  plain_text, 
                              FLASH_PAGE_SIZE - crypto_secretbox_NONCEBYTES,
                              (const unsigned char*) cipher_text,
                              (const unsigned char*) flash_key)) == -1)
        {
            safe_free(&cipher_text, FLASH_PAGE_SIZE);
            safe_free(&plain_text, FLASH_PAGE_SIZE - crypto_secretbox_NONCEBYTES);
            printf("Flash write failed: unable to encrypt the install table \n");
            return -1;
        }
    
        mesh_flash_write_page(cipher_text, page);
        new_offset += end_offset - current_offset;
        data += end_offset - current_offset;
    }
   
    safe_free(&cipher_text, FLASH_PAGE_SIZE);
    safe_free(&plain_text, FLASH_PAGE_SIZE - crypto_secretbox_NONCEBYTES);
   
    return 0;
}


/**
 * @brief Read "flash_length" number of bytes from "flash_location" into "data".
 *        Data read from flash is decrypted first
 * 
 * @param data pointer to a buffer with size=flash_length
 * @param flash_location location to read from in flash
 * @param flash_length number of bytes to read
 * @return 0 on success. !0 on failure
 */
int mesh_flash_read(void* data, unsigned int flash_location, unsigned int flash_length)
{
    /* Read "flash_length" number of bytes from "flash_location" into "data" */
    if (flash_length < 1)
        return 0;

    // malloc space to hold an entire page
    char* cipher_text = safe_calloc(1, sizeof(char) * FLASH_PAGE_SIZE);
    char* plain_text  = safe_calloc(1, sizeof(char) * FLASH_PAGE_SIZE - crypto_secretbox_NONCEBYTES);
    
    unsigned int new_offset = flash_location; 
    while (new_offset - flash_location < flash_length) {
        unsigned int page = new_offset / FLASH_CRYPTO_PAGE_SIZE;
        if (mesh_flash_read_page(cipher_text, page)) {
            return -1;
        }
        
        // nonce is equal to the first 24 bytes of ct
        if (crypto_secretbox_open((unsigned char*) plain_text, 
                         (const unsigned char*) &cipher_text[crypto_secretbox_NONCEBYTES], 
                         FLASH_PAGE_SIZE - crypto_secretbox_NONCEBYTES, 
                         (const unsigned char*) cipher_text,
                         (const unsigned char*) flash_key) == -1)
        {
            safe_free(&cipher_text, sizeof(char) * FLASH_PAGE_SIZE);
            safe_free(&plain_text, sizeof(char) * FLASH_PAGE_SIZE - crypto_secretbox_NONCEBYTES);
            return -1;
        }

        unsigned int current_offset = new_offset % (FLASH_CRYPTO_PAGE_SIZE);
        unsigned int end_offset = FLASH_CRYPTO_PAGE_SIZE;
       
        if (flash_location + flash_length - new_offset + current_offset < end_offset)
        {
            end_offset = flash_location + flash_length - new_offset + current_offset;
        }
       
        memcpy(data, &plain_text[crypto_secretbox_ZEROBYTES] + current_offset, 
               end_offset - current_offset);

        new_offset += end_offset - current_offset;
        data += end_offset - current_offset;
    }

    safe_free(&cipher_text, sizeof(char) * FLASH_PAGE_SIZE);
    safe_free(&plain_text, sizeof(char) * FLASH_PAGE_SIZE - crypto_secretbox_NONCEBYTES);

    return 0;
}


/******************************************************************************/
/******************************** End Flash Commands **************************/
/******************************************************************************/

/******************************************************************************/
/********************************** MESH Commands *****************************/
/******************************************************************************/


/**
 * @brief This function lists all commands available from the mesh shell.
 *        It implements the help function in the mesh shell. 
 * 
 * @param args arguments passed to the help command. They are ignored
 * @return 0 on success
 */
int mesh_help(char **args)
{
    /* List all valid commands */
    int i;
    printf("Welcome to the MITRE entertainment system\n");
    printf("The commands available to you are listed below:\n");

    for (i = 0; i < mesh_num_builtins(); i++)
    {
        printf("  %s\n", builtin_str[i]);
    }

    return 0;
}


/**
 * @brief This shuts down the mesh terminal. It does not shut down the board.
 *        This implements the shutdown function in the mesh shell.
 * 
 * @param args arguments passed to the shutdown command. They are ignored
 * @return never gets here
 */
int mesh_shutdown(char **args)
{
    /* Exit the shell completely */
    memset(user.name, 0, MAX_USERNAME_LENGTH + 1);
    memset(user.pin, 0, MAX_PIN_LENGTH + 1);
    char * const reset_argv[3] = {"reset"}; 
    cmd_tbl_t* reset_tp = find_cmd("reset");
    reset_tp->cmd(reset_tp, 1, 0, reset_argv);
    return MESH_SHUTDOWN;
}


/**
 * @brief Log the current user out of mesh. The control loop brings the user
 *        back to the login prompt. This implements the logout function in the 
 *        mesh shell.
 * 
 * @param args arguments passed to the logout command. They are ignored
 * @return 0 on success
 */
int mesh_logout(char **args)
{   
    /* Exit the shell, allow other user to login */
    memset(user.name, 0, MAX_USERNAME_LENGTH + 1);
    memset(user.pin, 0, MAX_PIN_LENGTH + 1);
    return 0;
}


/**
 * @brief List all installed games for the given user. This implements the list
 *        function in the mesh shell.
 * 
 * @param args arguments passed to the list command. They are ignored
 * @return 0 on success or failure
 */
int mesh_list(char **args)
{
    struct games_tbl_row *row;
    unsigned int index = 0;

    // loop through install table untill end of table is found.
    for(; index < installed_games_size; index++)
    {
        row = &installed_games[index];
        // print the game if it is found.
        if (strncmp(row->user_name, user.name, MAX_USERNAME_LENGTH) == 0 && row->install_flag == MESH_TABLE_INSTALLED)
            printf("%s-v%d.%d\n", row->game_name, row->major_version, row->minor_version);
    }

    return 0;
}


/**
 * @brief This function writes the specified game to ram address 0x1fc00040 and the
 *        size of the specified game binary to 0x1fc00000. It then boots the linux
 *        kernel from ram address 0x10000000. This allows the linux kernel to read the
 *        binary and execute it to play the game. 
 *        This function implements the play function in mesh. 
 * 
 * @param args arguments passed to the play command. ["play", "game_name"]
 * @return 0 on success or failure
 */
int mesh_play(char **args)
{
    if (!mesh_play_validate_args(args)){
        return 0;
    }

    Game game;
    loff_t size = 0;
    
    if((size = crypto_get_game_header(&game, args[1])) == -1) {
        return 0;
    }

    if (mesh_check_downgrade(args[1], game.major_version, game.minor_version) == 1){
        printf("You are not allowed to play an older version of the game once a newer one is installed.\n");
        return 0;
    }
    
    char *game_binary = safe_malloc(size);

    if(crypto_get_game(game_binary, args[1], &user) == -1){
        // This probably means its a bad user.
        return 0;
    }
    
    int casted_size = (int) size;
    // writes 11 byte size string (0x########) to 0x1fc00000 
    char *size_str = (char *)safe_malloc(MAX_INT_STR_LENGTH);
    if (snprintf(size_str, MAX_INT_STR_LENGTH,"0x%x", (int) casted_size) < 0) {
        mesh_shutdown(NULL);
    }
    char * const mw_argv[3] = { "mw.l", "0x1fc00000", size_str };
    cmd_tbl_t* mem_write_tp = find_cmd("mw.l");
    mem_write_tp->cmd(mem_write_tp, 0, 3, mw_argv);

    char *from_str = (char *)safe_malloc(MAX_INT_STR_LENGTH);
    if (snprintf(from_str, MAX_INT_STR_LENGTH, "0x%p", (void *) game_binary) < 0) {
        mesh_shutdown(NULL);
    }
    
    char * const cp_argv[4] = { "cp", from_str, "0x1fc00040",  size_str };
    cmd_tbl_t* cp_tp = find_cmd("cp");
    cp_tp->cmd(cp_tp, 0, 4, cp_argv);

    // cleanup - this is here because boot may not execute following commands
    safe_free(&from_str, MAX_INT_STR_LENGTH);
    safe_free(&size_str, MAX_INT_STR_LENGTH);
    safe_free(&game_binary, size);
    
    // boot petalinux
    char * const boot_argv[2] = { "bootm", "0x10000000"};
    cmd_tbl_t* boot_tp = find_cmd("bootm");
    boot_tp->cmd(boot_tp, 0, 2, boot_argv);

    return 0;
}


/**
 * @brief This function lists all games that are on the sd card that are available for installation
 * 
 * @param args arguments passed to the query command. They are ignored
 * @return 1 on success. 0 on failure
 */
int mesh_query(char **args)
{
    /* List all games available to download */
    printf("%s's games...\n", user.name);
    return mesh_query_ext4("/", NULL) < 0 ? 0 : 1;
}


/**
 * @brief This function installs the given game for the specified user.
 *        It finds the next available spot in the install table.
 *        It implements the install function of the mesh shell.
 * 
 * @param args arguments passed to the install command. ["install", "game_name"]
 * @return 0 on success or failure
 */
int mesh_install(char **args)
{
    /* Install the game */
    int validated = 0;
    if ((validated = mesh_install_validate_args(args))){
        return validated;
    }

    char* full_game_name = safe_malloc(MAX_GAME_LENGTH + 1);
    strncpy(full_game_name, args[1], MAX_GAME_LENGTH);

    // get the short name of the game (the stuff before the "-")
    char* short_game_name = strtok(full_game_name, "-");

    // get the major and minor version of the game
    char* major_version = strtok(NULL, ".") + 1;  // +1 becase of the "v"
    char* minor_version = strtok(NULL, "\0");

    // Row for this game
    struct games_tbl_row row;
    // Flag saying that this game is installed
    row.install_flag = MESH_TABLE_INSTALLED;

    // Copy the game name into our struct (padded with 0's)
    int i;
    for(i = 0; i < MAX_GAME_LENGTH && short_game_name[i] != '\0'; ++i)
        row.game_name[i] = short_game_name[i];
    for(; i < MAX_GAME_LENGTH; ++i)
        row.game_name[i] = 0;
    row.game_name[MAX_GAME_LENGTH] = 0;

    // copy the username into the struct (padded with 0's)
    for(i = 0; i <= MAX_USERNAME_LENGTH && user.name[i] != '\0'; ++i)
        row.user_name[i] = user.name[i];
    for(; i <= MAX_USERNAME_LENGTH; ++i)
        row.user_name[i] = 0;
    row.user_name[MAX_USERNAME_LENGTH] = 0;

    row.major_version = simple_strtoul(major_version, NULL, 10);
    row.minor_version = simple_strtoul(minor_version, NULL, 10);

    printf("Installing game %s for %s...\n", row.game_name, row.user_name);

    unsigned int index = 0;
    struct games_tbl_row *next;

    // look for the game in either a lower version or uninstalled
    for (; index < installed_games_size; index++) {
        next = &installed_games[index];
        if (strncmp(next->game_name, row.game_name, MAX_GAME_LENGTH) == 0 &&
            strncmp(next->user_name, row.user_name, MAX_USERNAME_LENGTH) == 0)
        {
            if (next->major_version < row.major_version ||
                (next->major_version == row.major_version && 
                next->minor_version < row.minor_version))
            {
                printf("Upgrading game %s for %s from version %u.%u to %u.%u...\n", row.game_name, row.user_name, 
                                                                                      next->major_version, next->minor_version,
                                                                                      row.major_version, row.minor_version);
            }
            memcpy(next, &row, sizeof(struct games_tbl_row));
            mesh_write_install_table();
            safe_free(&full_game_name, MAX_GAME_LENGTH + 1);
            return 0;
        }
    }

    // if the game was not found then we need to add it to the end of the table
    installed_games = safe_realloc(installed_games, sizeof(struct games_tbl_row) * ++installed_games_size);
    memcpy(&installed_games[installed_games_size - 1], &row, sizeof(struct games_tbl_row));

    // write the size and table to flash
    mesh_write_install_table();

    printf("%s was successfully installed for %s\n", row.game_name, row.user_name);
    safe_free(&full_game_name, MAX_GAME_LENGTH + 1);
    return 0;
}


/**
 * @brief This function uninstalls the specified game for the given user.
 * 
 * @param args arguments passed to the uninstall command. ["uninstall", "game_name"]
 * @return 0 on success or failure
 */
int mesh_uninstall(char **args)
{
    /* Remove the game for this user*/

    if (!mesh_game_installed(args[1])) {
        printf("%s is not installed for %s.\n", args[1], user.name);
        return 0;
    }

    struct games_tbl_row *row;
    unsigned int index = 0;
    size_t malloced_size = 0;

    printf("Uninstalling %s for %s...\n", args[1], user.name);
    for(; index < installed_games_size; index++)
    {
        row = &installed_games[index];
        // the most space that we could need to store the full game name
        malloced_size = snprintf(NULL, 0, "%s-v%d.%d", row->game_name, row->major_version, row->minor_version) + 1;      
        if (malloced_size > 0) {
            char* full_name = (char*) safe_malloc(malloced_size);
            full_name_from_short_name(full_name, row, malloced_size);

            if (strncmp(row->user_name, user.name, MAX_USERNAME_LENGTH) == 0 &&
                strncmp(full_name, args[1], malloced_size) == 0 &&
                row->install_flag == MESH_TABLE_INSTALLED)
            {
                row->install_flag = MESH_TABLE_UNINSTALLED;
                mesh_write_install_table();
                printf("%s was successfully uninstalled for %s\n", args[1], user.name);
                safe_free(&full_name, malloced_size);
                break;
            }
            safe_free(&full_name, malloced_size);
        }
    }

    return 0;
}

/******************************************************************************/
/******************************** End MESH Commands ***************************/
/******************************************************************************/


/******************************************************************************/
/******************************** MESH Command Loop *****************************/
/******************************************************************************/


/**
 * @brief This is the main control loop for the mesh shell.
 */
void mesh_loop(void) {
    char *line;
    char **args;
    int status = 1;
    int login_count = 0;

    memset(user.name, 0, MAX_USERNAME_LENGTH + 1);
    memset(user.pin, 0, MAX_PIN_LENGTH + 1);

    mesh_flash_init();
    if (mesh_is_first_table_write())
    {
        printf("Performing first time setup...\n");
        mesh_init_table();
        printf("Done!\n");
    }
    mesh_get_install_table();

    // Perform first time initialization to ensure that the default
    // games are present
    strncpy(user.name, "demo", MAX_USERNAME_LENGTH);
    strncpy(user.pin, "00000000", MAX_PIN_LENGTH);

    for(int i = 0; i < NUM_DEFAULT_GAMES; ++i)
    {
        char* install_args[] = {"install", default_games[i], '\0'};
        int ret_code = mesh_install(install_args);
        // only continued if the game install was successful or the game
        // was already installed
        if (ret_code != 0 && ret_code != INSTALL_DOWNGRADE && 
            ret_code != INSTALL_INSTALLED)
        {
            printf("Error detected while installing default games\n");
            return;
        }
        
        // additional check to make sure that the game is really installed
        Game game;

        if (crypto_get_game_header(&game, default_games[i]) == -1 ||
            !mesh_check_user(&game) ||
            !(mesh_game_installed(default_games[i]) || 
            mesh_check_downgrade(default_games[i], 
                                 game.major_version, 
                                 game.minor_version)))
        {
            printf("Error detected while installing default games\n");
            return;
        }

    }

    memset(user.name, 0, MAX_USERNAME_LENGTH + 1);
    memset(user.pin, 0, MAX_PIN_LENGTH + 1);

    while(1)
    {
        int login = mesh_login(&user);
        if (login && !(!(login))) {
            if (++login_count >= MAX_LOGIN_ATTEMPTS) {
                printf("Exceeded maximum login limit. Please try again in 5-seconds ... \n");
                mdelay(LOGIN_TIMEOUT); 
            }
            continue;
        }
        login_count = 0;

        while(*(user.name)) {
            line = mesh_input(CONFIG_SYS_PROMPT);

            // This is the run_command function from common/cli.c:29
            // if this is uncommented, then it checks first in the builtins in
            // for the hush shell then for the command. This allows you to use
            // all the builtin commands when developing.
            // if (!run_command(line, 0)){
            // }

            args = mesh_split_line(line);
            status = mesh_execute(args);
            safe_free(&args, sizeof(char*) * MESH_TOK_BUFSIZE);

            safe_free(&line, sizeof(char) * MAX_STR_LEN);

            // -2 for exit
            if (status == MESH_SHUTDOWN)
                break;
        }
        if (status == MESH_SHUTDOWN)
            break;
    }
}

/******************************************************************************/
/****************************** End MESH Command Loop ***************************/
/******************************************************************************/

/******************************************************************************/
/*********************************** MESH Ext4 ********************************/
/******************************************************************************/


/**
 * @brief This is a modified version of ext4fs_iterate_dir from ext4_common.c:1994
 *        It has the same usage as the original function, however, it only prints out
 *        regular files on the partition.
 *        If fname is specified, then no text is written to std out and it returns 1
 *        if the filename is found in dir and 0 otherwise.
 *        If fname is not specified, then it lists all files in dir to std out.
 * 
 * @param dir directory to iterate
 * @param fname filename to look for
 * 
 * @return 0 on success. !0 on failure
 */
int mesh_ls_iterate_dir(struct ext2fs_node *dir, char *fname)
{
    Game game;
    unsigned int fpos = 0;
    unsigned int game_num = 1;
    int status;
    loff_t actread;
    loff_t chk;
    struct ext2fs_node *diro = (struct ext2fs_node *) dir;

    if (!diro->inode_read) {
        status = ext4fs_read_inode(diro->data, diro->ino, &diro->inode);
        if (status == 0)
            return 0;
    }
    /* Search the file.  */
    while (fpos < le32_to_cpu(diro->inode.size)) {
        struct ext2_dirent dirent;

        status = ext4fs_read_file(diro, fpos,
                       sizeof(struct ext2_dirent),
                       (char *)&dirent, &actread);
        if (status < 0)
            return 0;

        if (dirent.direntlen == 0) {
            printf("Failed to iterate over directory\n");
            return 0;
        }

        if (dirent.namelen != 0) {
            char filename[dirent.namelen + 1];
            struct ext2fs_node *fdiro;
            int type = FILETYPE_UNKNOWN;

            status = ext4fs_read_file(diro,
                          fpos +
                          sizeof(struct ext2_dirent),
                          dirent.namelen, filename,
                          &actread);
            if (status < 0)
                return 0;

            fdiro = zalloc(sizeof(struct ext2fs_node));
            if (!fdiro)
                return 0;

            fdiro->data = diro->data;
            fdiro->ino = le32_to_cpu(dirent.inode);

            filename[dirent.namelen] = '\0';

            if (dirent.filetype != FILETYPE_UNKNOWN) {
                fdiro->inode_read = 0;

                if (dirent.filetype == FILETYPE_DIRECTORY)
                    type = FILETYPE_DIRECTORY;
                else if (dirent.filetype == FILETYPE_SYMLINK)
                    type = FILETYPE_SYMLINK;
                else if (dirent.filetype == FILETYPE_REG)
                    type = FILETYPE_REG;
            } else {
                status = ext4fs_read_inode(diro->data,
                               le32_to_cpu
                               (dirent.inode),
                               &fdiro->inode);
                if (status == 0) {
                    safe_free(&fdiro, sizeof(struct ext2fs_node));
                    return 0;
                }
                fdiro->inode_read = 1;

                if ((le16_to_cpu(fdiro->inode.mode) &
                     FILETYPE_INO_MASK) ==
                    FILETYPE_INO_DIRECTORY) {
                    type = FILETYPE_DIRECTORY;
                } else if ((le16_to_cpu(fdiro->inode.mode)
                        & FILETYPE_INO_MASK) ==
                       FILETYPE_INO_SYMLINK) {
                    type = FILETYPE_SYMLINK;
                } else if ((le16_to_cpu(fdiro->inode.mode)
                        & FILETYPE_INO_MASK) ==
                       FILETYPE_INO_REG) {
                    type = FILETYPE_REG;
                }
            }

            if (fname != NULL) {
                if (type == FILETYPE_REG && strncmp(filename, fname, dirent.namelen + 1) == 0) {
                    return 1;
                }
            } else {
                if (fdiro->inode_read == 0) {
                    status = ext4fs_read_inode(diro->data,
                                 le32_to_cpu(
                                 dirent.inode),
                                 &fdiro->inode);
                    if (status == 0) {
                        safe_free(&fdiro, sizeof(struct ext2fs_node));
                        return 0;
                    }
                    fdiro->inode_read = 1;
                }
                switch (type) {
                case FILETYPE_REG:
                    // only print name if the user is in valid install list
                    chk = crypto_get_game_header(&game, filename);
                    if (chk == -1) {
                        mesh_shutdown(NULL);
                    }
                    
                    if (mesh_check_user(&game)){
                        printf("%d      ", game_num++);
                        printf("%s\n", filename);
                    }

                    break;
                default:
                    break;
                }
            }
            safe_free(&fdiro, sizeof(struct ext2fs_node));
        }
        fpos += le16_to_cpu(dirent.direntlen);
    }
    return 0;
}


/**
 * @brief This is derived from the ext4fs_ls function in ext4fs.c:158
 *        It is meant to be a standalone function by setting the correct
 *        device to read from and then querying files from the custom mesh
 *        file iterator.
 * 
 * @param dirname name of the directory being traversed
 * @param filename filename being searched for
 * 
 * @return 0 on success. !0 on failure
 */
int mesh_ls_ext4(const char *dirname, char *filename)
{
    int ret = 0;

    struct ext2fs_node *dirnode;
    int status;

    if (dirname == NULL)
        return 0;

    status = ext4fs_find_file(dirname, &ext4fs_root->diropen, &dirnode,
                  FILETYPE_DIRECTORY);
    if (status != 1) {
        printf("** Can not find directory. **\n");
        return -1;
    }

    ret = mesh_ls_iterate_dir(dirnode, filename);

    return ret;
}


/**
 * @brief This is derived from the ext4fs_ls function in ext4fs.c:158
 *        It is meant to be a standalone function by setting the correct
 *        device to read from and then querying files from the custom mesh
 *        file iterator.
 * 
 * @param dirname name of the directory being traversed
 * @param filename filename being searched for
 * 
 * @return 0 on success. !0 on failure
 */
int mesh_query_ext4(const char *dirname, char *filename){

    int ret = 0;

    if(fs_set_blk_dev("mmc", "0:2", FS_TYPE_EXT) < 0){
        return -1;
    }

    // fs/fs.c:281
    ret = mesh_ls_ext4(dirname, filename);

    ext4fs_close();

    return ret;
}


/**
 * @brief This function gets the size of a file on a ext4 partion. It uses the
 *        u-boot ext4 fs functions to determine the size.
 * 
 * @param fname name of the file that we are getting the size of.
 * @return size of fname. -1 on error
 */
loff_t mesh_size_ext4(char *fname){
    loff_t size;    

    if(fs_set_blk_dev("mmc", "0:2", FS_TYPE_EXT) < 0){
        return -1;
    }

    // fs/fs.c:281
    ext4fs_size(fname, &size);

    ext4fs_close();

    return size;
}

/**
 * @brief reads size bytes into buf from a file on a ext4 partition
 * 
 * @param fname name of the file being read from
 * @param buf pointer to the buffer that we are reading data to
 * @param size max number of bytes to read
 * @return the number of bytes read. -1 on error
 */
loff_t mesh_read_ext4(char *fname, char*buf, loff_t size){
    loff_t actually_read;
    

    if(fs_set_blk_dev("mmc", "0:2", FS_TYPE_EXT) < 0){
        return -1;
    }

    if(ext4_read_file(fname, buf, 0, size, &actually_read) < 0) {
        return -1;
    }

    ext4fs_close();

    return actually_read;
}

/******************************************************************************/
/******************************* End MESH Ext4 ********************************/
/******************************************************************************/

/******************************************************************************/
/************************************* Helpers ********************************/
/******************************************************************************/

/**
 * @brief safely calls malloc. powersoff the board if malloc failed
 * 
 * @param size number of bytes to malloc
 * @return a pointer to the buffer malloced
 */
void *safe_malloc(size_t size){
    void *p = malloc(size);
    if(p == NULL){
        // If bad malloc, exit
        mesh_shutdown(NULL);
    }
    return p;
}

/**
 * @brief safely calls calloc powersoff the board if calloc failed
 * 
 * @param nitems the number of elements to be allocated
 * @param size number of bytes to malloc
 * @return a pointer to the buffer calloced
 */
void *safe_calloc(size_t nitems, size_t size){
    void *p = calloc(nitems, size);
    if(p == NULL){
        // If bad malloc, exit
        mesh_shutdown(NULL);
    }
    return p;
}

/**
 * @brief safely calls realloc powersoff the board if realloc failed
 * 
 * @param ptr pointer to the previously malloced buffer
 * @param size number of bytes to malloc
 * @return a pointer to the buffer realloced
 */
void *safe_realloc(void *ptr, size_t size){
    void *p = realloc(ptr, size);
    if(p == NULL){
        // If bad malloc, exit
        mesh_shutdown(NULL);
    }
    return p;
}

/*
 * @brief Clears memory before freeing. Also sets the pointer to NULL
 *
 * @params ptr A pointer to the memory to free
 * @params size The size of the memory to be freed
 */
void safe_free(void** ptr, size_t size){
    if (*ptr == NULL) {return;}
    memset(*ptr, 0, size);
    free(*ptr);
    *ptr = NULL;
}

/**
 * @brief gets the full_game_name from an install record
 * 
 * @param full_name buffer to store the full name
 * @param row install record used to grab the game name, major version, and minor version
 */
void full_name_from_short_name(char* full_name, struct games_tbl_row* row, size_t len) {
    if (snprintf(full_name, len,"%s-v%d.%d", row->game_name, row->major_version, row->minor_version)  < 0) 
    {
        mesh_shutdown(NULL);
    }
}


/**
 * @brief This function determines if the specified game is installed for the given
 *        user at the same version. It returns 1 if it is installed and 0 if it isnt.
 * 
 * @param game_name full name of a game that is being checked
 * @return 1 if installed. 0 otherwise
 */
int mesh_game_installed(char *game_name){
    struct games_tbl_row *row;
    unsigned int index = 0;
    size_t malloced_size = 0;

    // loop through install table until table end is found
    for(; index < installed_games_size; index++)
    {
        row = &installed_games[index];
        // the most space that we could need to store the full game name
        malloced_size = snprintf(NULL, 0, "%s-v%d.%d", row->game_name, row->major_version, row->minor_version) + 1;      
        if (malloced_size > 0){
            char* full_name = (char*) safe_malloc(malloced_size);
            full_name_from_short_name(full_name, row, malloced_size);

            // check if game is installed and if it is for the specified user.
            if (strncmp(game_name, full_name, MAX_GAME_LENGTH) == 0 &&
                strncmp(user.name, row->user_name, MAX_USERNAME_LENGTH) == 0 &&
                row->install_flag == MESH_TABLE_INSTALLED)
            {
                safe_free(&full_name, malloced_size);
                return 1;
            }
            safe_free(&full_name, malloced_size);
        }
    }

    return 0;
}


/**
 * @brief This function validates the arguments for mesh play. It returns 1 if the
 *        arguments are valid and 0 if they are not. It will print usage help and any
 *        pertinent warnings.
 * 
 * @param args arguments passed into mesh_play. ["play", "game_name"]
 * @return 1 on success. 0 on failure
 */
int mesh_play_validate_args(char **args){
    // ensure a game name is listed
    int argv = mesh_get_argv(args);
    if (argv < 2){
        printf("No game name specified.\n");
        printf("Usage: play [GAME NAME]\n");
        return 0;
    } else if (argv > 2){
        printf("Warning, more than one argument specified, install first game specified.\n");
    }

    // assert game length is valid
    for (int count=0; args[1][count] != 0; count++){
        if (count > MAX_GAME_LENGTH) {
            printf("Specified game exceeds maximum game name length of %d\n", MAX_GAME_LENGTH);
            return 0;
        }
    }

    // assert game exists in filesystem
    if (!mesh_game_installed(args[1])){
        printf("%s is not installed for %s.\n", args[1], user.name);
        return 0;
    }

    return 1;
}


/**
 * @brief This function determines if a game exists on the ext4 partition of the
 *        sd card with the given game_name. It returns 1 if it is found and 0 if it
 *        is not.
 * 
 * @param game_name name of the game that we are checking exists on the ext4 partition
 * @return 0 on success. !0 on failure
 */
int mesh_game_exists(char *game_name)
{
    /* List all games available to download */
    return mesh_query_ext4("/", game_name) == 1;
}


/**
 * @brief This function determines if the specified user can install the given game.
 * 
 * @param game name of the game to be checked
 * @return 1 on success. 0 on failure
 */
int mesh_check_user(Game *game)
{
    for (int i=0; i<game->num_users; i++){
        if (strncmp(game->users[i], user.name, MAX_USERNAME_LENGTH) == 0){
            return 1;
        }
    }

    return 0;
}


/**
 * @brief This function determines if you are downgrading the specified game.
 *        Returns 0 on downgrade, 1 otherwise
 * 
 * @param game_name full name of the game
 * @param major_version major version of the game
 * @param minor_version minor version of the game
 * @return 0 on success. !0 on failure
 */
int mesh_check_downgrade(char *game_name, unsigned int major_version, unsigned int minor_version)
{
    struct games_tbl_row *row;
    unsigned int index = 0;
    int return_value = 0;

    for(; index < installed_games_size; index++)
    {
        row = &installed_games[index];
        // Ignore anyone that isn't the current user
        if (strncmp(user.name, row->user_name, MAX_USERNAME_LENGTH) != 0)
            continue;

        // ignore it if it doesn't have the same game name
        // must make a copy, otherwise, it modified game_name, which under the covers is args[1]
        char short_game_name[MAX_GAME_LENGTH + 1] = "";
        strncpy(short_game_name, game_name, MAX_GAME_LENGTH);
        strtok(short_game_name, "-");
        if (strncmp(short_game_name, row->game_name, MAX_GAME_LENGTH) != 0)
            continue;

        // Fail if the major version of the new game is less than the currently
        // installed game
        if (major_version < row->major_version)
        {
            return_value = 1;
        }
        // Fail if the major version of the new game is the same and the minor
        // version is less or the same
        else if (major_version == row->major_version && minor_version < row->minor_version)
        {
            return_value = 1;
        }
        // prevent a reinstall of the same version without an uninstall
        else if (major_version == row->major_version &&
            minor_version == row->minor_version &&
            row->install_flag == MESH_TABLE_INSTALLED)
        {
            return_value = return_value == 1 ? return_value : 2;
        }
    }
    return return_value;
}

/**
 * @brief checks if a game_name can be installed.
 * 
 * @param game_name name of the game
 * @return 0 on success. !0 on failure
 *         3 if the game doesn't exist
 *         4 if the current user is not allowed to install the game
 *         5 if a later version of the game is already installed
 *         6 if the game is already installed
 *         7 if no more games can be installed
 *         8 if the game signature could not be verified
 */
int mesh_valid_install(char *game_name){
    if (!mesh_game_exists(game_name)){
        printf("Game doesnt exist\n");
        return INSTALL_NO_GAME_EXISTS;
    }

    Game game;
    // mesh_get_game_header(&game, game_name);
    if (crypto_get_game_header(&game, game_name) == -1) {
        return INSTALL_INVALID_SIGNATURE;
    }

    if (!mesh_check_user(&game)){
        return INSTALL_USER_NOT_ALLOWED;
    }
    if (mesh_game_installed(game_name)){
        return INSTALL_INSTALLED;
    }
    if (mesh_check_downgrade(game_name, game.major_version, game.minor_version)){
        return INSTALL_DOWNGRADE;
    }
    if (installed_games_size == MAX_GAMES_INSTALLED) {
        return INSTALL_LIMIT_REACHED;
    }

    return 0;
}


/**
 * @brief This function validates the arguments for mesh_install. If the arguments are
 *        valid it returns 1 and otherwise returns 0.
 *        
 * 
 * @param args arguments passed into mesh_install. ["install", "game_name"]
 * @return 0 on success. !0 on failure
 *         1 if the game name is not defined
 *         2 if the length of the game name is too long
 *         3 if the game doesn't exist
 *         4 if the current user is not allowed to install the game
 *         5 if a later version of the game is already installed
 *         6 if the game is already installed
 *         7 if no more games can be installed
 *         8 if the game signature could not be verified
 *         -1 on any other error
 */
int mesh_install_validate_args(char **args){
    // ensure a game name is listed
    int errno = 0;
    int argv = mesh_get_argv(args);
    if (argv < 2){
        printf("No game name specified.\n");
        printf("Usage: install [GAME NAME]\n");
        return 1;
    } else if (argv > 2){
        printf("Warning, more than one argument specified, install first game specified.\n");
    }

    // assert game length is valid
    for (int count=0; args[1][count] != 0; count++){
        if (count > MAX_GAME_LENGTH) {
            printf("Specified game exceeds maximum game name length of %d\n", MAX_GAME_LENGTH);
            return INSTALL_INVALID_LENGTH;
        }
    }

    char *game_name = args[1];

    // assert game exists in filesystem
    errno = mesh_valid_install(game_name);
    switch (errno) {
        case 0 :
            break;
        case INSTALL_NO_GAME_EXISTS:
            printf("Error installing %s, the game does not exist on the SD card games partition.\n", game_name);
            return INSTALL_NO_GAME_EXISTS;
        case INSTALL_USER_NOT_ALLOWED:
            printf("Error installing %s, %s is not allowed to install this game.\n", game_name, user.name);
            return INSTALL_USER_NOT_ALLOWED;
        case INSTALL_DOWNGRADE:
            printf("Error installing %s, downgrade not allowed. Later version is already installed.\n", game_name);
            return INSTALL_DOWNGRADE;
        case INSTALL_INSTALLED:
            printf("Skipping install of %s, game is already installed.\n", game_name);
            return INSTALL_INSTALLED;
        case INSTALL_LIMIT_REACHED:
            printf("No more games can be installed\n");
            return INSTALL_LIMIT_REACHED;
        case INSTALL_INVALID_SIGNATURE:
            printf("Unable to verify signature on game %s\n", game_name);
            return INSTALL_INVALID_SIGNATURE;
        default :
            printf("Unknown error installing game.\n");
            return INSTALL_UNKNOWN_ERROR;
    }

    return 0;
}


/**
 * @brief This function executes the specified command for the given user.
 *        It finds the command in builtin_func and then calls the function with the
 *        args for the given user.
 *
 * @param args arguments passed in from the mesh_prompt
 * @return the return value from whatever command was run.
 *         defaults to 1 if no command was found
 */
int mesh_execute(char **args) {
    int i;

    if (args[0] == NULL) {
        // An empty command was entered.
        return 1;
    }

    for (i = 0; i < mesh_num_builtins(); i++) {
        if (strncmp(args[0], builtin_str[i], MAX_BUILTIN_STR_LEN) == 0) {
            return (*builtin_func[i])(args);
        }
    }

    printf("Not a valid command\n");
    printf("Use help to get a list of valid commands\n");
    return 1;
}


/**
 * @brief This is a helper function to convert a character point to a hex string
 *        beginning with 0x. This is used for converting values to u-boot parameters
 *        which expects hex strings.
 * 
 * @param ptr pointer that we are converting to a string
 * @param buf buffer that we are storing the string in
 */
void ptr_to_string(void* ptr, char* buf)
{
    /* Given a pointer and a buffer of length 11, returns a string of the poitner */
    if (snprintf(buf, MAX_INT_STR_LENGTH, "0x%x", (unsigned int) ptr) < 0) {
        mesh_shutdown(NULL);
    }
    buf[MAX_INT_STR_LENGTH - 1] = 0;
}


/**
 * @brief This function determines if the sentinel is written to flash addres
 *        MESH_SENTINEL_LOCATION yet. If it is then it returns 1, otherwise, it returns
 *        0.
 *
 * @return 0 if the sentinel is found. 1 otherwise
 */
int mesh_is_first_table_write(void)
{
    /* Initialize the table where games will be installed */
    char* sentinel = (char*) safe_malloc(sizeof(char) * MESH_SENTINEL_LENGTH);
    int ret = 0;

    ret = mesh_flash_read(sentinel, MESH_SENTINEL_LOCATION, MESH_SENTINEL_LENGTH);

    if (ret || *((unsigned int*) sentinel) != MESH_SENTINEL_VALUE)
    {
        ret = 1;
    }
    safe_free(&sentinel, sizeof(char) * MESH_SENTINEL_LENGTH);
    return ret;
}


/**
 * @brief This function determines if the specified user and pin is listed in the 
 *        mesh_users array. If it is then the user is logged in and the function
 *        returns 1. Otherwise, it returns 0.
 * 
 * @param user struct to store the username and pin for comparison
 * @return 0 if the username and pin are correct. 1 otherwise
 */
int mesh_validate_user(User *user)
{
    /* Validates that the username and pin match a combination
     * provisioned with the board. This is read from the
     * mesh_users.h header file.
     * Retruns 0 on success and 1 on failure. */
    for (int i = 0; i < NUM_MESH_USERS; ++i)
    {
        if (strncmp(mesh_users[i].username, user->name, MAX_USERNAME_LENGTH) == 0) {
            // second check is implemented within bcrypt so the hash is not calculated twice
            int bcrypt = bcrypt_checkpass(user->pin, mesh_users[i].hash); 
            if ((bcrypt == 0) && (!(!(bcrypt == 0)))) {
                return 0;
            }
            else {
                return 1;
            }
        }
    }
    // run bcrypt even if the user is not found
    bcrypt_checkpass(user->pin, default_hash);
    return 1;
}


/**
 * @brief This function determines the number of builtin functions in the mesh
 *        shell.
 * @return the number of builtin functions
 */
int mesh_num_builtins(void) {
    return sizeof(builtin_str) / sizeof(char *);
}


/**
 * @brief This function reads a line from stdin and returns a pointer to the character
 *        buffer containing the null terminated line. 
 *        This funciton allocates the charater buffer on the heap, therefore, the caller
 *        must free this buffer to avoid a memory leak.
 * 
 * @param bufsize max size of the buffer to read
 * @return a buffer of the line read
 */
char* mesh_read_line(int bufsize)
{
    int position = 0;
    char *buffer = (char*) safe_malloc(sizeof(char) * bufsize);
    int c;

    while (1) {
        // Read a character
        c = getc();

        if (position == bufsize - 1) {
            printf("\b");
        }
        if (c == '\n' || c == '\r') {
            printf("\n");
            buffer[position] = '\0';
            return buffer;
        }
        else if (c == '\b' || c == 0x7F) // backspace
        {
            if (position)
            {
                position--;
                buffer[position] = '\0';
                printf("\b \b");
            }
        }
        else {
            buffer[position] = c;
            if (position < bufsize - 1)
            {
                position++;
            }
            printf("%c", c);
        }
    }
}


/**
 * @brief This function determines the number of arguments specified in args and
 *        returns that number..
 * 
 * @param args array of arguments
 * @return the number of arguments in args
 */
int mesh_get_argv(char **args){
    int count = 0;

    for (int i=0; args[i]; i++){
        count++;
    }

    return count;
}


/**
 * @brief This function is used to split a single line of command line arguments
 *        into an array of individual arguments.
 *        It returns an array of character buffers. Both this array and the character
 *        buffers are allocated on the heap and therefore, it is the responsibility of
 *        the caller to free this memory after the arguments are used.
 * 
 * @param line pointer to the line of arguments to split
 * @return array of arguments
 */
char **mesh_split_line(char *line) {
    int bufsize = MESH_TOK_BUFSIZE, position = 0;
    char **tokens = (char**) safe_malloc(bufsize * sizeof(char*));
    char *token, **tokens_backup;

    token = strtok(line, MESH_TOK_DELIM);
    while (token != NULL) {
        tokens[position] = token;
        position++;

        if (position >= bufsize) {
            bufsize += MESH_TOK_BUFSIZE;
            tokens_backup = tokens;
            tokens = safe_realloc(tokens, bufsize * sizeof(char*));
            if (!tokens) {
                safe_free(&tokens_backup, bufsize * sizeof(char*));
            }
        }

        token = strtok(NULL, MESH_TOK_DELIM);
    }
    tokens[position] = NULL;
    return tokens;
}


/**
 * @brief This function prompts from user input from stdin and returns a point to
 *        that read line. Note, this is line is created using mesh_read_line and thus
 *        it is the responsibility of the caller to free the character buffer.
 * 
 * @param prompt what shows for users to enter commands "mesh>"
 * @return a pointer to the line read from the user
 */
char* mesh_input(char* prompt)
{
    printf("%s",prompt);
    return mesh_read_line(MAX_STR_LEN);
}

/**
 * @brief Get all of the installed games from flash and place them in RAM
 */
void mesh_get_install_table(void)
{
    int ret = mesh_flash_read(&installed_games_size, MESH_INSTALL_GAME_OFFSET, sizeof(unsigned int));

    // there cannot be more than MAX_GAMES installed so when that happens we know that an attack has occured
    if (ret || installed_games_size > MAX_GAMES_INSTALLED) {
        mesh_init_table();
    }

    if (installed_games_size > 0) {
        installed_games = safe_malloc(sizeof(struct games_tbl_row) * installed_games_size);
        ret = mesh_flash_read( installed_games,
                         MESH_INSTALL_GAME_OFFSET + sizeof(unsigned int), 
                         sizeof(struct games_tbl_row) * installed_games_size);
        if (ret) {
            installed_games_size = 0;
            safe_free(&installed_games, sizeof(struct games_tbl_row) * installed_games_size);
            mesh_init_table();
        }
    }
}


/**
 * @brief write all of the installed games from RAM into FLASH. Including the sentinel value
 *        and install table size
 */
void mesh_write_install_table(void)
{
    unsigned int write_size = 2*sizeof(unsigned int) + installed_games_size*sizeof(struct games_tbl_row);
    char *write_buffer = safe_malloc(write_size);
    unsigned int sentinel_value = MESH_SENTINEL_VALUE;
    memcpy(write_buffer, &sentinel_value, sizeof(unsigned int));
    memcpy(write_buffer+sizeof(unsigned int), &installed_games_size, sizeof(unsigned int));
    if (installed_games_size > 0) {
        memcpy(write_buffer+sizeof(unsigned int)*2, installed_games, installed_games_size*sizeof(struct games_tbl_row));
    }
    mesh_flash_write(write_buffer, MESH_SENTINEL_LOCATION, write_size);
    safe_free(&write_buffer, write_size);
}


/**
 * @brief This function handles logging in a user. It prompts for a username and pin.
 *        If a valid user pin combo is read, it writes the name and pin to the user
 *        struct and returns 0, otherwise, it returns an error code
 * 
 * @param user struct for storing the user credentials after successfully logging in
 * @return 0 on success. !0 on failure
 */
int mesh_login(User *user) {
    User tmp_user;

    char *tmp_name, *tmp_pin;
    int retval;

    memset(user->name, 0, MAX_USERNAME_LENGTH + 1);
    memset(user->pin, 0, MAX_PIN_LENGTH + 1);

    do {
        tmp_name = mesh_input("Enter your username: ");
    } while (!strnlen(tmp_name, MAX_USERNAME_LENGTH));

    do {
        tmp_pin = mesh_input("Enter your PIN: ");
    } while (!strnlen(tmp_pin, MAX_PIN_LENGTH));

    strncpy(tmp_user.name, tmp_name, MAX_USERNAME_LENGTH + 1);
    strncpy(tmp_user.pin, tmp_pin, MAX_PIN_LENGTH + 1);

    /* if valid user, copy into user */
    retval = mesh_validate_user(&tmp_user);
    if (!retval && !(!(!retval))) {
        strncpy(user->name, tmp_user.name, MAX_USERNAME_LENGTH);
        strncpy(user->pin, tmp_user.pin, MAX_PIN_LENGTH);
    } else {
        printf("Login failed. Please try again\n");
    }

    safe_free(&tmp_name, sizeof(char) * MAX_STR_LEN);
    safe_free(&tmp_pin, sizeof(char) * MAX_STR_LEN);

    return retval;
}


/**
 * @brief set a random buffer of size crypto_secretbox_NONCEBYTES bytes
 * 
 * @param buf pointer to the buffer to store the random nonce
 */
static void random_nonce(char* buf)
{
    int round = 0;
    unsigned int output;

    while(round++ < crypto_secretbox_NONCEBYTES/(sizeof output))
    {
        output = rand(); 
        strncpy(buf, (char*) &output, sizeof output);
        buf += sizeof output;
    }
}
