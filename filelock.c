/* pr0nlock.c - file encryption using OpenSSL's implementation of blowfish 
 * author: Eugene Ma (edma2)
 */
#include <openssl/blowfish.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>

#define PW_SIZE         30
#define IV_SIZE         8
#define BF_BLOCK_SIZE   8
#define HEADER_SIZE     9

typedef union {
        uint64_t iv64;
        uint8_t iv8[sizeof(uint64_t)];
} IVec;

int main(int argc, char *argv[]) {
        uint8_t pw[PW_SIZE];
        uint8_t header[HEADER_SIZE];
        uint8_t buf_in[BF_BLOCK_SIZE];
        uint8_t keystream[BF_BLOCK_SIZE];
        uint8_t buf_out[BF_BLOCK_SIZE];
        uint64_t filelen;
        uint8_t last_block_size;
        int mode;
        int read_count, write_count = 0;
        int i;
        FILE *fp;
        time_t tm;
        IVec iv;
        BF_KEY key;
        struct termios term, term_orig;

        /* take care of the arguments and set encryption mode */
        if (argc == 2) {
                mode = BF_ENCRYPT;
                fp = fopen(argv[1], "r");
        } else if (argc == 3) {
                if (strcmp(argv[1], "-e") == 0) {
                        mode = BF_ENCRYPT;
                } else if (strcmp(argv[1], "-d") == 0) {
                        mode = BF_DECRYPT;
                } else {
                        fprintf(stderr, "error: use flags -e for encryption and -d for decryption\n");
                        return -1;
                }
                fp = fopen(argv[2], "r");
        } else {
                fprintf(stderr, "usage: pr0nlock [flag] <file>\n");
                return -1;
        }
        if (fp == NULL) {
                fprintf(stderr, "error: unable to open file for reading\n");
                return -1;
        }

        /* disable terminal echo */
        tcgetattr(STDIN_FILENO, &term);
        term_orig = term;
        term.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &term);
        /* get password */
        fprintf(stderr, "Enter password: ");
        fgets((char *)pw, PW_SIZE, stdin);
        fprintf(stderr, "\n");
        /* restore terminal echo */
        tcsetattr(STDIN_FILENO, TCSANOW, &term_orig);

        /* initialize the key */
        BF_set_key(&key, strlen((char *)pw), pw);

        /*
         * Prepare 9 byte header consisting of the initialization
         * vector and the pad length of the file 
         */
        if (mode == BF_ENCRYPT) {
                /* 
                 * Seed random number generator with unix time
                 * and pass random number to IV 
                 */
                tm = time(NULL);
                srandom(tm);
                /* Use all 64 bits */
                iv.iv64 = ((uint64_t)random() << 32) | random();
                for (i = 0; i < IV_SIZE; i++)
                        header[i] = iv.iv8[i];
                /* get length of file */
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
                last_block_size = filelen % BF_BLOCK_SIZE;
                if (last_block_size == 0)
                        last_block_size = BF_BLOCK_SIZE;
                header[i] = last_block_size;
                rewind(fp);
                /* write 9 byte header - IV and filelen */
                if (fwrite(header, sizeof(uint8_t), HEADER_SIZE, stdout) != HEADER_SIZE) {
                        fprintf(stderr, "error: unable to write header\n");
                        fclose(fp);
                        return -1;
                }
        } else if (mode == BF_DECRYPT) {
                /* retrieve initilization vector */
                if (fread(iv.iv8, sizeof(uint8_t), IV_SIZE, fp) < 0) {
                        fprintf(stderr, "error: unable to read file\n");
                        fclose(fp);
                        return -1;
                }
                /* retreive offset information */
                if (fread(&last_block_size, sizeof(uint8_t), 1, fp) != 1) {
                        fprintf(stderr, "error: unable to read file\n");
                        fclose(fp);
                        return -1;
                }
        }
        /* read from file and write to stdout */
        while ((read_count = fread(buf_in, sizeof(uint8_t), BF_BLOCK_SIZE, fp)) > 0) {
                if (mode == BF_ENCRYPT) {
                        /* add necessary padding */
                        for (; read_count < BF_BLOCK_SIZE; read_count++)
                                buf_in[read_count] = 0;
                }
                if (fwrite(buf_out, sizeof(uint8_t), write_count, stdout) != write_count) {
                        fprintf(stderr, "error: write error\n");
                        break;
                }
                BF_ecb_encrypt(iv.iv8, keystream, &key, BF_ENCRYPT);
                iv.iv64++;
                for (i = 0; i < BF_BLOCK_SIZE; i++)
                        buf_out[i] = keystream[i] ^ buf_in[i];
                write_count = BF_BLOCK_SIZE;
        }
        /* write the last block, taking the file offset into
         * account if program is in decrypt mode */
        write_count = ((mode == BF_ENCRYPT) ? BF_BLOCK_SIZE : last_block_size);
        if (fwrite(buf_out, sizeof(uint8_t), write_count, stdout) != write_count)
                fprintf(stderr, "error: write error\n");

        fclose(fp);
        return 0;
}
