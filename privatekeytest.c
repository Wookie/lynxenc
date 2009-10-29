#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include "keys.h"
#include "loaders.h"
#include "privatekeydata.h"

#define min(x,y) ((x < y) ? x : y)

void print_number(BIGNUM *number)
{
    int i;
    char* p = BN_bn2hex(number);

    while(*p)
    {
        for(i = 0; (i < 8) && (*p); i++)
        {
            printf("0x%c%c, ", p[0], p[1]);
            p += 2;
        }
        printf("\n");
    }
    printf("\n");
}

void print_data(const unsigned char * data, int size)
{
    int i = 0;
    int j, count;
    int left = size;

    while(i < size)
    {
        count = min(8, (size - i));

        printf("    ");
        for(j = 0; j < count; j++)
        {
            printf("0x%02x, ", data[i + j]);
        }
        printf("\n");
        i += count;
    }
}

void print_data_reverse(const unsigned char * data, int size)
{
    int i;
    unsigned char * tmp = calloc(1, size);
    unsigned char * p = tmp;

    for(i = size - 1; i >= 0; i--)
    {
        (*p) = data[i];
        p++;
    }

    print_data(tmp, size);
    free(tmp);
}

BIGNUM* load_reverse(const unsigned char* buf, const int length)
{
    BIGNUM* bn;
    int i;
    const unsigned char* ptr = buf;
    unsigned char* tmp = calloc(1, length);

    for(i = length - 1; i >= 0; i--)
    {
        tmp[i] = *ptr;
        ptr++;
    }

    bn = BN_bin2bn(tmp, length, 0);
    free(tmp);
    return bn;
}

BIGNUM* load(const unsigned char* buf, const int length)
{
    return BN_bin2bn(buf, length, 0);
}


void decrypt_block(unsigned char * out,
                   const unsigned char * in,
                   const int block_length,
                   BIGNUM * exponent,
                   BIGNUM * modulus,
                   BN_CTX * ctx)
{
    BIGNUM * result = BN_new();

    /* load the data to process */
    BIGNUM * block = load(in, block_length);

    /* do the RSA step */
    BN_mod_exp(result, block, exponent, modulus, ctx);

    /* copy the result to the output buffer */
    BN_bn2bin(result, out);

    /* free up the result bignum */
    BN_free(result);
}

/* this lets me try different permutations of the key files to generate
 * different possible decrypted private keys */
void do_rsa(unsigned char * out,
            const unsigned char * encrypted,
            const unsigned char * exponent,
            const unsigned char * modulus)
{
    BIGNUM * bn_exponent = load(exponent, CHUNK_LENGTH);
    BIGNUM * bn_modulus = load(modulus, CHUNK_LENGTH);
    BN_CTX *ctx = BN_CTX_new();

    /* zero out the result */
    memset(out, 0, CHUNK_LENGTH);

    /* decrypt the block of data */
    decrypt_block(out, encrypted, CHUNK_LENGTH, bn_exponent, bn_modulus, ctx);

    BN_free(bn_modulus);
    BN_free(bn_exponent);
    BN_CTX_free(ctx);
}

void check(const unsigned char * msg,
           const unsigned char * in,
           const unsigned char * received,
           const unsigned char * expected)
{
    if (memcmp(received, expected, CHUNK_LENGTH) == 0)
        printf("%s: Worked!\n", msg);
    else
    {
        printf("%s: Failed!\n", msg);
        printf("Tried:\n");
        print_data(in, CHUNK_LENGTH);
        printf("Received:\n");
        print_data(received, CHUNK_LENGTH);
        printf("Expected:\n");
        print_data(expected, CHUNK_LENGTH);
        printf("\n");
    }
}

int main (int argc, const char * argv[]) 
{
    unsigned char result[CHUNK_LENGTH];
    unsigned char lynx_private_exp[CHUNK_LENGTH];

    /* according to the documentation on RSA, the way the public/private exponents
     * are related is that encryption works like so:
     * 
     * encrypted = (plaintext ^ private_exp) % public_mod
     *
     * decryption, which we already have working, works like this:
     *
     * plaintext = (encrypted ^ public_exp) % public_mod
     *
     * Now, we have the public_exp and the public_mod values.  We also have
     * known good values for plaintext and encrypted.
     */

    /* first do known good inputs and outputs to verify the steps are working */
    do_rsa(result, reversed_encrypted_block1_frame1, 
           lynx_public_exp, lynx_public_mod);
    check("Known good data", reversed_encrypted_block1_frame1,
           result, obfuscated_block1_frame1);
    
    /* try encrypting with each individual key file first...who knows, maybe the
     * private exponent isn't encrypted */
    do_rsa(result, obfuscated_block1_frame1, keyfile_1, lynx_public_mod);
    check("Plain keyfile.1", obfuscated_block1_frame1, 
          result, reversed_encrypted_block1_frame1);
    do_rsa(result, obfuscated_block1_frame1, keyfile_2, lynx_public_mod);
    check("Plain keyfile.2", obfuscated_block1_frame1, 
          result, reversed_encrypted_block1_frame1);
    do_rsa(result, obfuscated_block1_frame1, keyfile_3, lynx_public_mod);
    check("Plain keyfile.3", obfuscated_block1_frame1, 
          result, reversed_encrypted_block1_frame1);
    
    /* now try to decode the private key based on Karri's guess */
    do_rsa(lynx_private_exp, keyfile_1, keyfile_2, keyfile_3);

    /* then try to encrypt the known good data */
    do_rsa(result, obfuscated_block1_frame1,
           lynx_private_exp, lynx_public_mod);
    check("Priv Exp: 1, Prot Exp: 2, Prot Mod: 3", 
          obfuscated_block1_frame1, result, 
          reversed_encrypted_block1_frame1);
    
    return 0;
}
