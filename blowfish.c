/* blowfish.c - password protected file encryption 
 * author: Eugene Ma (edma2)
 */
#include <openssl/blowfish.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#define PW_SIZE         30
#define IV_SIZE         8
#define BF_BLOCK_SIZE   8
#define HEADER_SIZE     16

int main(int argc, char *argv[]) {
        uint8_t pw[PW_SIZE];
        uint8_t iv[IV_SIZE] = { 0 };
        uint8_t header[HEADER_SIZE];
        uint8_t buf_in[BF_BLOCK_SIZE];
        uint8_t buf_out[BF_BLOCK_SIZE];
        uint64_t filelen;
        FILE *fp;
        BF_KEY key;
        int mode, count;
        int i;
        struct termios term, term_orig;

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

        /* Disable terminal echo */
        tcgetattr(STDIN_FILENO, &term);
        term_orig = term;
        term.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &term);
        /* Get password */
        fprintf(stderr, "Enter password: ");
        fgets((char *)pw, PW_SIZE, stdin);
        fprintf(stderr, "\n");
        /* Restore terminal echo */
        tcsetattr(STDIN_FILENO, TCSANOW, &term_orig);

        /* Initialize the key */
        BF_set_key(&key, strlen((char *)pw), pw);

        /*
         * Prepare 16 byte header consisting of the initialization
         * vector and information about the length of the file 
         */
        if (mode == BF_ENCRYPT) {
                /*
                 * Get initialization vector
                 * TODO: use entropy bits
                 */
                for (i = 0; i < IV_SIZE; i++)
                        header[i] = iv[i];

                /* Get length of file */
                if (fseek(fp, 0, SEEK_END) < 0) {
                        fprintf(stderr, "error: unable to obtain file length\n");
                        fclose(fp);
                        return -1;
                }
                filelen = ftell(fp);
                if (filelen < 0) {
                        fprintf(stderr, "error: unable to obtain file length\n");
                        fclose(fp);
                        return -1;
                }
                *(uint64_t *)(header + IV_SIZE) = filelen;
                rewind(fp);

                /* Write 16-byte header - IV and filelen */
                if (fwrite(header, sizeof(uint8_t), HEADER_SIZE, stdout) != HEADER_SIZE) {
                        fprintf(stderr, "error: unable to write header\n");
                        fclose(fp);
                        return -1;
                }
        } else if (mode == BF_DECRYPT) {
                /* Retrieve initilization vector */
                if (fread(iv, sizeof(uint8_t), IV_SIZE, fp) < 0) {
                        fprintf(stderr, "error: unable to read file\n");
                        fclose(fp);
                        return -1;
                }

                /* Retreive length of file */
                if (fread(&filelen, sizeof(uint64_t), 1, fp) != 1) {
                        fprintf(stderr, "error: unable to read file\n");
                        fclose(fp);
                        return -1;
                }
        }

        /* Read from file and write to stdout */
        while ((count = fread(buf_in, sizeof(uint8_t), BF_BLOCK_SIZE, fp)) > 0) {
                //fprintf(stderr, "%d\n", count);
                if (mode == BF_ENCRYPT) {
                        /* Add necessary padding */
                        for (; count < BF_BLOCK_SIZE; count++)
                                buf_in[count] = 0;
                } else if (mode == BF_DECRYPT) {
                        /* Keep track of file length
                         * Check for file offset when we reach the last
                         * block. */
                        if (count > filelen)
                                count = filelen;
                        else
                                filelen -= count;
                }
                /* CBC mode - initialization vector set to 0 */
                BF_cbc_encrypt(buf_in, buf_out, BF_BLOCK_SIZE, &key, iv, mode);
                if (fwrite(buf_out, sizeof(uint8_t), count, stdout) != count) {
                        fprintf(stderr, "error: write error\n");
                        break;
                }
        }
        fclose(fp);

        return 0;
}
