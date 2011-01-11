#include <openssl/blowfish.h>
#include <stdint.h>
include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#define PW_SIZE         30
#define BF_BLOCK_SIZE   8
#define IV_SIZE         8

int main(int argc, char *argv[]) {
        uint8_t pw[PW_SIZE];
        uint8_t iv[IV_SIZE] = { 0 };
        uint8_t buf_in[BF_BLOCK_SIZE];
        uint8_t buf_out[BF_BLOCK_SIZE];
        FILE *fp;
        BF_KEY key;
        int mode, count;
        int i = 0;
        struct termios term, term_orig;

        /* Disable terminal echo */
        tcgetattr(STDIN_FILENO, &term);
        term_orig = term;
        term.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &term);
        
        /* Take care of the arguments and set encryption mode */
        if (argc == 2) {
                mode = BF_ENCRYPT;
                fp = fopen(argv[1], "r");
        } else if (argc == 3) {
                if (strcmp(argv[1], "-e") == 0)
                        mode = BF_ENCRYPT;
                else if (strcmp(argv[1], "-d") == 0)
                        mode = BF_DECRYPT;
                else {
                        fprintf(stderr, "error: use flags -e for encryption and -d for decryption\n");
                        return -1;
                }
                fp = fopen(argv[2], "r");
        } else {
                fprintf(stderr, "usage: bf [flag] <file>\n");
                return -1;
        }

        if (fp == NULL) {
                fprintf(stderr, "error: unable to open file for reading\n");
                return -1;
        }

        /* Get password */
        fprintf(stderr, "Enter password: ");
        scanf("%s", pw);
        fprintf(stderr, "\n");

        /* Restore terminal echo */
        tcsetattr(STDIN_FILENO, TCSANOW, &term_orig);

        /* Initialize the key */
        BF_set_key(&key, strlen((char *)pw), pw);

        /* Read from file and write to stdout */
        while ((count = fread(buf_in, sizeof(uint8_t), BF_BLOCK_SIZE, fp)) > 0) {
                /* Encryption input and output should always be
                 * eight bytes, so add padding if we read less 
                 * than eight bytes. */
                for (i = BF_BLOCK_SIZE; i > count; i--) 
                        buf_in[i] = 0;
                /* CBC mode - initialization vector set to 0 */
                BF_cbc_encrypt(buf_in, buf_out, BF_BLOCK_SIZE, &key, iv, mode);
                if (fwrite(buf_out, sizeof(uint8_t), BF_BLOCK_SIZE, stdout) != BF_BLOCK_SIZE) {
                        fprintf(stderr, "error: write error\n");
                        break;
                }
        }
        fclose(fp);

        return 0;
}
