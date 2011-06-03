/* filelock.c - file encryption using OpenSSL's implementation of blowfish 
 * Author: Eugene Ma (edma2)
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

typedef union {
        uint64_t iv64;
        uint8_t iv8[sizeof(uint64_t)];
} IVec;

int main(int argc, char *argv[]) {
        FILE *fin, *fout;

        uint8_t pw[PW_SIZE];
        uint8_t buf_in[BF_BLOCK_SIZE], buf_out[BF_BLOCK_SIZE];
        uint8_t keystream[BF_BLOCK_SIZE];
        uint8_t last_block_size;
        int read_count, write_count;
        time_t tm;
        IVec iv;

        struct termios term, term_orig;
        FILE *kb;
        int kbfd;
        BF_KEY key;

        uint8_t c;
        int mode, i;

        /* Check correct argument count */
        if (argc != 4) {
                fprintf(stderr, "Usage: filelock <mode> <input file> <output file>\n");
                return -1;
        }

        /* Check and get mode */
        if ((c = getopt(argc, argv, "de")) < 0) {
                fprintf(stderr, "Usage: available modes are e, d");
                return -1;
        }
        mode = (c == 'e') ? BF_ENCRYPT : BF_DECRYPT;

        /* Open input stream from stdin or file */
        if (argv[2][0] != '\0' && argv[2][0] == '-' && argv[2][1] == '\0') {
                /* Use stdin */
                fin = stdin;
        } else {
                /* Open file for reading */
                fin = fopen(argv[2], "r");
                if (fin == NULL) {
                        fprintf(stderr, "Error: unable to open %s for reading\n", argv[2]);
                        return -1;
                }
        }

        /* Set output stream to stdout or file */
        if (argv[3][0] == '-' && argv[3][1] == '\0') {
                /* Use stdout */
                fout = stdout;
        } else {
                /* Open file for writing */
                fout = fopen(argv[3], "w+");
                if (fout == NULL) {
                        fprintf(stderr, "Error: unable to open %s for writing\n", argv[3]);
                        fclose(fin);
                        return -1;
                }
        }

        /* Open input stream from keyboard */
        kb = fopen("/dev/tty", "r");
        if (kb != NULL) {
                kbfd = fileno(kb);
                if (kbfd < 0) {
                        fprintf(stderr, "Error: unable to open tty\n");
                        fclose(fin);
                        fclose(fout);
                        remove(argv[3]);
                        fclose(kb);
                        return -1;
                }
        } else {
                fprintf(stderr, "Error: unable to open tty\n");
                fclose(fin);
                fclose(fout);
                remove(argv[3]);
                return -1;
        }

        /* Disable terminal echo */
        tcgetattr(kbfd, &term);
        term_orig = term;
        term.c_lflag &= ~ECHO;
        tcsetattr(kbfd, TCSANOW, &term);

        /* Get password */
        fprintf(stderr, "Enter password: ");
        fgets((char *)pw, PW_SIZE, kb);
        fprintf(stderr, "\n");

        /* Restore terminal echo and close input stream */
        tcsetattr(kbfd, TCSANOW, &term_orig);
        fclose(kb);

        /* Initialize the key */
        BF_set_key(&key, strlen((char *)pw), pw);

        /*  Generate and write initialization vector */
        if (mode == BF_ENCRYPT) {
                /* Write dummy 0 byte first. We overwrite it later after we know last block size */
                c = 0;
                if (fwrite(&c, sizeof(uint8_t), 1, fout) != 1) {
                        fprintf(stderr, "Error: unable to write initialization vector\n");
                        fclose(fin);
                        fclose(fout);
                        remove(argv[3]);
                        return -1;
                }

                /* Seed random number generator with unix time and pass random number to IV */
                tm = time(NULL);
                srandom(tm);

                /* Use all 64 bits of initialization vector by ORing 2 32-bit random ints */
                iv.iv64 = ((uint64_t)random() << 32) | random();

                /* Write initialization vector */
                if (fwrite(iv.iv8, sizeof(uint8_t), IV_SIZE, fout) != IV_SIZE) {
                        fprintf(stderr, "Error: unable to write initialization vector\n");
                        fclose(fin);
                        fclose(fout);
                        remove(argv[3]);
                        return -1;
                }
        } else if (mode == BF_DECRYPT) {
                /* Recover offset information */
                if (fread(&last_block_size, sizeof(uint8_t), 1, fin) < 0) {
                        fprintf(stderr, "Error: unable to read offset\n");
                        fclose(fin);
                        fclose(fout);
                        remove(argv[3]);
                        return -1;
                }

                /* Recover initialization vector */
                if (fread(iv.iv8, sizeof(uint8_t), IV_SIZE, fin) < 0) {
                        fprintf(stderr, "Error: unable to read initialization vector\n");
                        fclose(fin);
                        fclose(fout);
                        remove(argv[3]);
                        return -1;
                }
        }

        /* Delay write by skipping first iteration */
        write_count = 0;

        /* Main loop */
        while ((read_count = fread(buf_in, sizeof(uint8_t), BF_BLOCK_SIZE, fin)) > 0) {
                /* Add necessary padding and record offset on last block */
                if (mode == BF_ENCRYPT) {
                        last_block_size = read_count;
                        for (; read_count < BF_BLOCK_SIZE; read_count++)
                                buf_in[read_count] = 0;
                }

                /* Write previous block */
                if (fwrite(buf_out, sizeof(uint8_t), write_count, fout) != write_count) {
                        fprintf(stderr, "Error: write error\n");
                        fclose(fin);
                        fclose(fout);
                        remove(argv[3]);
                        break;
                }

                /* Encrypt or decrypt block */
                BF_ecb_encrypt(iv.iv8, keystream, &key, BF_ENCRYPT);
                iv.iv64++;
                for (i = 0; i < BF_BLOCK_SIZE; i++)
                        buf_out[i] = keystream[i] ^ buf_in[i];
                write_count = BF_BLOCK_SIZE;
        }

        /* Must write last block since reads lead writes by 1 iteration */
        write_count = ((mode == BF_ENCRYPT) ? BF_BLOCK_SIZE : last_block_size);
        if (fwrite(buf_out, sizeof(uint8_t), write_count, fout) != write_count) {
                fprintf(stderr, "Error: write error\n");
                fclose(fin);
                fclose(fout);
                remove(argv[3]);
                return -1;
        }

        /* Rewind to beginning and overwrite dummy byte with last_block_size */
        if (mode == BF_ENCRYPT) {
                rewind(fout);
                if (fwrite(&last_block_size, sizeof(uint8_t), 1, fout) != 1) {
                        fprintf(stderr, "Error: unable to write initialization vector\n");
                        fclose(fin);
                        fclose(fout);
                        remove(argv[3]);
                        return -1;
                }
        }

        /* Clean up */
        fclose(fin);
        fclose(fout);

        return 0;
}
