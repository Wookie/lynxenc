#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include "keys.h"
#include "loaders.h"

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

int decode_block(unsigned char* out,
                 const unsigned char *in,
                 const int block_length,
                 int accumulator,
                 BIGNUM * exponent,
                 BIGNUM * modulus,
                 BN_CTX * ctx)
{
    int i,j;
    unsigned char * p;
    unsigned char * o = out;

    /* allocate the output conversion buffer */
    p = calloc(1, block_length);

    /* create a result buffer */
    BIGNUM * result = BN_new();

    /* load the block */
    BIGNUM * block = load_reverse(in, block_length);

    /* do the RSA step */
    BN_mod_exp(result, block, exponent, modulus, ctx);

    /* unreverse the data out, and convert it */
    /* NOTE: we only take 50 bytes of output, not 51, the
     * byte as index 0 of the p buffer is carry cruft. */
    BN_bn2bin(result, p);
    for(i = block_length - 1; i > 0; i --)
    {
        accumulator += p[i];
        accumulator &= 0xFF;
        (*o) = (unsigned char)(accumulator);
        o++;
    }

    /* free the result */
    BN_free(result);

    /* free the output conversion buffer */
    free(p);

    return accumulator;
}

int decode_frame(unsigned char* out,
                 const unsigned char* in,
                 const int block_length,
                 BIGNUM * exponent,
                 BIGNUM * modulus,
                 BN_CTX * ctx)
{
    int i;
    int accumulator = 0;
    int blocks = 256 - (*in);
    const unsigned char* p = (++in);

    for(i = 0; i < blocks; i++)
    {
        accumulator = decode_block(out, p, block_length, accumulator, exponent, modulus, ctx);
        p += block_length;
        out += (block_length - 1);
    }

    return blocks;
}

int generic_lynx_decrypt(unsigned char * out,
                         const unsigned char * encrypted,
                         const int block_length)
{
    int blocks = 0;
    int read_index = 0;
    BIGNUM *exponent = BN_bin2bn(lynx_public_exp, block_length, 0);
    BIGNUM *modulus = BN_bin2bn(lynx_public_mod, block_length, 0);
    BN_CTX *ctx = BN_CTX_new();

    /* decode the first frame of encrypted data */
    blocks = decode_frame(&out[0],
                          &HarrysEncryptedLoader[read_index],
                          block_length,
                          exponent, modulus, ctx);

    /* adjust the read index */
    read_index = 1 + (blocks * CHUNK_LENGTH);

    /* decode the second frame of encrypted data */
    blocks = decode_frame(&out[256],
                          &HarrysEncryptedLoader[read_index],
                          block_length,
                          exponent, modulus, ctx);

    BN_free(modulus);
    BN_free(exponent);
    BN_CTX_free(ctx);
}

int main (int argc, const char * argv[]) 
{
    unsigned char result[FULL_LOADER_LENGTH];

    /* zero out the output buffer */
    memset(result, 0, FULL_LOADER_LENGTH);

    /* decrypt the encrypted loader using the OpenSSL bignum library to
     * do the RSA step. */
    generic_lynx_decrypt(result, HarrysEncryptedLoader, CHUNK_LENGTH);

    /* compare the results */
    if(memcmp(result, HarrysFullPlaintextLoader, FULL_LOADER_LENGTH) == 0)
        printf("Generic Lynx Decrypt Works!\n");
    else
        printf("Generic Lynx Decrypt Fails!\n");

    return 0;
}
