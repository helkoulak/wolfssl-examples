/* Ascon-Hash256.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ascon.h>

#ifdef HAVE_ASCON
void usage(void)
{
    printf("./Ascon-Hash256 <file to hash>\n");
    exit(-99);
}
#endif

void free_mem(wc_AsconHash256 *asconHash, byte *hash, byte *rawInput, FILE *inputStream) {
    if (asconHash != NULL) {
        wc_AsconHash256_Free(asconHash);
    }
    if (rawInput != NULL) {
        free(rawInput);
    }
    if (inputStream != NULL) {
        fclose(inputStream);
    }
    if (hash != NULL) {
        free(hash);
    }
}

int main(int argc, char** argv)
{
    int ret = 0;
#ifdef HAVE_ASCON
    wc_AsconHash256* asconHash = NULL;
    byte*  hash = NULL;
    byte*  rawInput = NULL;
    FILE* inputStream = NULL;
    char* fName = NULL;
    int fileLength = 0;

    if (argc < 2)
        usage();
    fName = argv[1];
    printf("Hash input file %s\n", fName);

    while (1) {
        inputStream = fopen(fName, "rb");
        if (inputStream == NULL) {
            printf("ERROR: Unable to open file\n");
            ret = -1;
            break;
        }

        /* find length of the file */
        fseek(inputStream, 0, SEEK_END);
        fileLength = (int) ftell(inputStream);
        fseek(inputStream, 0, SEEK_SET);

        /* Create and initialize hash context */
        asconHash = wc_AsconHash256_New();
        if (asconHash == NULL) {
            printf("ERROR: Unable to create the hash context\n");
            ret = -1;
            break;
        }

        hash = (byte*) malloc(ASCON_HASH256_SZ);
        if (hash == NULL) {
            printf("ERROR: Unable to allocate space for hash value\n");
            ret = -1;
            break;
        }

        rawInput = (byte*) malloc(fileLength);
        if (rawInput == NULL) {
            printf("ERROR: Unable to allocate space for raw input\n");
            ret = -1;
            break;
        }

        /* Read input file into a byte array*/
        size_t read = fread(rawInput, 1, fileLength, inputStream);
        if (read != fileLength) {
            printf("ERROR: Failed to read the size of input file\n");
            ret = -1;
            break;
        }

        ret = wc_AsconHash256_Update(asconHash, rawInput, fileLength);
        if (ret != 0) {
            printf("ERROR: Hash update failed\n");
            ret = -1;
            break;
        }

        ret = wc_AsconHash256_Final(asconHash, hash);
        if (ret != 0) {
            printf("ERROR: Hash operation failed");
            ret = -1;
            break;
        }
        break;
    }

    printf("Hash result is: ");
    for (int i = 0; i < ASCON_HASH256_SZ; i++)
        printf("%02x", hash[i]);
    printf("\n");

    free_mem(asconHash, hash, rawInput, inputStream);
#else
    printf("Please enable Ascon-Hash256 (--enable-ascon --enable-experimental) in wolfCrypt\n");
#endif
    return ret;
}
