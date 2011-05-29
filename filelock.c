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

#define TMP_PATH        "/tmp/filelock.tmp"

typedef union {
        uint64_t iv64;
        uint8_t iv8[sizeof(uint64_t)];
} IVec;

void clean(int mode, FILE *fp_in, FILE *fp_out, FILE *fp_tmpout) {
        fclose(fp_in);
        fclose(fp_out);
        /* Close and remove temporary file, if it in encrypt mode */
        if (mode == BF_ENCRYPT) {
                fclose(fp_tmpout);
                if (remove(TMP_PATH) < 0)
                        fprintf(stderr, "Error: unable to delete temporary file\n");
        }
}

int main(int argc, char *argv[]) {
        char c;
        uint8_t pw[PW_SIZE];
        uint8_t buf_in[BF_BLOCK_SIZE], buf_out[BF_BLOCK_SIZE];
        uint8_t keystream[BF_BLOCK_SIZE];
        uint8_t last_block_size;
        int mode;
        int read_count, write_count;
        int i;
        FILE *fp_in, *fp_out, *fp_tmpout;
        time_t tm;
        IVec iv;
        BF_KEY key;
        struct termios term, term_orig;

        uint8_t buf[8];
        int count;

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

        /*****************************************************************************/
        /* Open necessary files */
        /*****************************************************************************/

        /* Set input input stream to stdin or file */
        if (argv[2][0] == '-' && argv[2][1] == '\0') {
                /* Use stdin */
                fp_in = stdin;
        } else {
                /* Open file for reading */
                fp_in = fopen(argv[2], "r");
                if (fp_in == NULL) {
                        fprintf(stderr, "Error: unable to open %s for reading\n", argv[2]);
                        return -1;
                }
        }
        
        /* Set output stream to stdout or file */
        if (argv[3][0] == '-' && argv[3][1] == '\0') {
                /* Use stdout */
                fp_out = stdout;
        } else {
                /* Open file for writing */
                fp_out = fopen(argv[3], "w+");
                if (fp_out == NULL) {
                        fprintf(stderr, "Error: unable to open %s for writing\n", argv[3]);
                        fclose(fp_in);
                        return -1;
                }

        }

        /* 
         * If encrypt, open a temporary file to write to. Later we will 
         * write this to the real output file. Necessary because if input 
         * option is stdin we cannot know file length beforehand.
         */
        if (mode == BF_ENCRYPT) {
                fp_tmpout = fopen(TMP_PATH, "w+");
                if (fp_tmpout == NULL) {
                        fprintf(stderr, "Error: unable to open %s for writing\n", TMP_PATH);
                        fclose(fp_in);
                        fclose(fp_out);
                        return -1;
                }
        }

        /*****************************************************************************/
        /* Get password from user */
        /*****************************************************************************/

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

        /*****************************************************************************/
        /* Prepare for encryption or decryption */
        /*****************************************************************************/

        /*  Generate and write initialization vector */
        if (mode == BF_ENCRYPT) {
                /* Seed random number generator with unix time and pass random number to IV */
                tm = time(NULL);
                srandom(tm);

                /* Use all 64 bits of initialization vector by ORing 2 32-bit random ints */
                iv.iv64 = ((uint64_t)random() << 32) | random();

                /* Write IV to tmp file */
                if (fwrite(iv.iv8, sizeof(uint8_t), IV_SIZE, fp_tmpout) != IV_SIZE) {
                        fprintf(stderr, "Error: unable to write initialization vector\n");
                        clean(mode, fp_in, fp_out, fp_tmpout);
                        return -1;
                }
        } else if (mode == BF_DECRYPT) {
                /* Recover offset information */
                if (fread(&last_block_size, sizeof(uint8_t), 1, fp_in) < 0) {
                        fprintf(stderr, "Error: unable to read offset\n");
                        clean(mode, fp_in, fp_out, fp_tmpout);
                        return -1;
                }

                /* Recover initialization vector */
                if (fread(iv.iv8, sizeof(uint8_t), IV_SIZE, fp_in) < 0) {
                        fprintf(stderr, "Error: unable to read initialization vector\n");
                        clean(mode, fp_in, fp_out, fp_tmpout);
                        return -1;
                }
        }

        /*****************************************************************************/
        /* Main loop */
        /*****************************************************************************/

        /* If decrypt, just write to fp_out */
        fp_tmpout = fp_tmpout;
        while ((read_count = fread(buf_in, sizeof(uint8_t), BF_BLOCK_SIZE, fp_in)) > 0) {
                /* Add necessary padding and record offset on last block */
                if (mode == BF_ENCRYPT) {
                        last_block_size = read_count;
                        for (; read_count < BF_BLOCK_SIZE; read_count++)
                                buf_in[read_count] = 0;
                }

                /* Delayed write - skip first iteration */
                write_count = 0;
                if (fwrite(buf_out, sizeof(uint8_t), write_count, fp_tmpout) != write_count) {
                        fprintf(stderr, "Error: write error\n");
                        clean(mode, fp_in, fp_out, fp_tmpout);
                        break;
                }

                /* Encrypt or decrypt block */
                BF_ecb_encrypt(iv.iv8, keystream, &key, BF_ENCRYPT);
                iv.iv64++;
                for (i = 0; i < BF_BLOCK_SIZE; i++)
                        buf_out[i] = keystream[i] ^ buf_in[i];

                /* Update write count for next iteration */
                write_count = BF_BLOCK_SIZE;
        }

        /* Must write last block since reads lead writes by 1 iteration */
        write_count = ((mode == BF_ENCRYPT) ? BF_BLOCK_SIZE : last_block_size);
        if (fwrite(buf_out, sizeof(uint8_t), write_count, fp_tmpout) != write_count) {
                clean(mode, fp_in, fp_out, fp_tmpout);
                fprintf(stderr, "Error: write error\n");
                return -1;
        }

        /* 
         * If encrypt, write offset information to fp_out 
         * and transfer contents of fp_tmpout to fp_out.
         */
        if (mode == BF_ENCRYPT) {
                /* Write offset as first byte of output file */
                if (fwrite(&last_block_size, sizeof(uint8_t), 1, fp_out) < 0) {
                        fprintf(stderr, "Error: unable to write offset\n");
                        clean(mode, fp_in, fp_out, fp_tmpout);
                        return -1;
                }

                /* Copy file contents of temporary file to real output file */
                rewind(fp_tmpout);
                while ((count = fread(buf, sizeof(uint8_t), 8, fp_tmpout)) > 0) {
                        if (fwrite(buf, sizeof(uint8_t), 8, fp_out) != count) {
                                fprintf(stderr, "Error: write error\n");
                                break;
                        }
                }
        }

        clean(mode, fp_in, fp_out, fp_tmpout);
        return 0;
}
