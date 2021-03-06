/* sha1sum.c - calculate the SHA1 checksum of a file, prints to stdout
 * author: Eugene Ma (edma2)
 */
#include <openssl/sha.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 512
#define HASHSIZE 20

int hash_file(FILE *fp, char *hash);

int main(int argc, char *argv[]) {
        char hash[BUFSIZE];
        char line[BUFSIZE];
        char *check_path;
        char *check_hash;
        FILE *fp, *fp_check;
        int r;
        int flag = 0;

        /* Take care of the arguments */
        if (argc > 1) {
                /* Check for flag */
                if (argc == 3)
                        flag = !strcmp(argv[1], "-c");
        } else {
                fprintf(stderr, "Usage: sha1 [flag] <file>...\n");
                return -1;
        }

        if (flag) {
                /* Open the checksum file for checking */
                fp = fopen(argv[2], "r");
                if (fp == NULL) {
                        fprintf(stderr, "sha1: error opening file %s\n", argv[2]);
                        return -1;
                }
                while (fgets(line, BUFSIZE, fp) > 0) {
                        line[strlen(line)-1] = '\0';

                        check_hash = strtok(line, " ");
                        check_path = strtok(NULL, " ");

                        /* Open each file specified in the checksum file */
                        fp_check = fopen(check_path, "r");
                        if (fp_check == NULL) {
                                fprintf(stderr, "sha1: error opening file %s\n", check_path);
                                fclose(fp);
                                return -1;
                        }
                        if (hash_file(fp_check, hash) < 0) {
                                fclose(fp_check);
                                fclose(fp);
                                fprintf(stderr, "sha1: error hashing file\n");
                                return -1;
                        }
                        /* Compare previous hash with current hash */
                        if (strcmp(check_hash, hash) != 0) {
                                fprintf(stderr, "sha1sum: file %s corrupted\n", check_path);
                                fprintf(stderr, "original >  %s\n", check_hash);
                                fprintf(stderr, "new      <  %s\n", hash);
                        }
                        /* Close original final */
                        fclose(fp_check);
                }
                /* Close checksum file */
                fclose(fp);
        } else {
                /* Write a checksum for each filename */
                for (r = 1; r < argc; r++) {
                        /* Open file for reading */
                        fp = fopen(argv[r], "r");
                        if (fp == NULL) {
                                fprintf(stderr, "sha1: error opening file %s\n", argv[r]);
                                return -1;
                        }
                        if (hash_file(fp, hash) < 0) {
                                fclose(fp);
                                fprintf(stderr, "sha1: error hashing file\n");
                                return -1;
                        }
                        printf("%s  %s\n", hash, argv[r]);
                        fclose(fp);
                }
        }

        return 0;
}

/* Store hash bytes in hash, return -1 on error, 0 otherwise */
int hash_file(FILE *fp, char *hash) {
        SHA_CTX ctx;
        uint8_t buf[BUFSIZE];
        uint8_t raw_hash[HASHSIZE];
        char byte[2];
        int count;
        int i, j;

        if (!SHA1_Init(&ctx)) {
                fprintf(stderr, "sha1: could not initialize SHA_CTX struct\n");
                return -1;
        }

        /* Pass BUFSIZE bytes at a time to struct */
        while ((count = fread(buf, sizeof(uint8_t), BUFSIZE, fp)) > 0) {
                /* Pass count bytes from buf to struct */
                if (!SHA1_Update(&ctx, buf, count)) {
                        fprintf(stderr, "sha1: could not update struct SHA_CTX\n");
                        return -1;
                }
        }
        if (!SHA1_Final(raw_hash, &ctx)) {
                fprintf(stderr, "sha1: could not finalize struct SHA_CTX\n");
                return -1;
        }

        /* Write to string */
        for (i = 0, j = 0; i < HASHSIZE; i++) {
                /* Format into hexadecimals */
                snprintf(byte, 3, "%02x", raw_hash[i]);
                hash[j++] = byte[0];
                hash[j++] = byte[1];
        }
        hash[j] = '\0';

        return 0;
}
