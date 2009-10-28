#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keys.h"
#include "loaders.h"

#define CHUNK_LENGTH (51)
#define min(x,y) ((x < y) ? x : y)

/* helper function for dumping out blocks of data in a human readable form */
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


/* BB = 2 * BB */
void double_value(unsigned char *BB, const int length)
{
    int i, x;

    x = 0;
    for (i = length - 1; i >= 0; i--) 
    {
	    x += 2 * BB[i];
	    BB[i] = (unsigned char) (x & 0xFF);
	    x >>= 8;
    }
    /* shouldn't carry */
}

/* BB -= NN */
int minus_equals_value(unsigned char *BB, 
                       const unsigned char *NN, 
                       const int length)
{
    int i, x;
    unsigned char *T;

    /* allocate temporary buffer */
    T = calloc(1, length);

    x = 0;
    for (i = length - 1; i >= 0; i--) 
    {
	    x += BB[i] - NN[i];
	    T[i] = (unsigned char) (x & 0xFF);
	    x >>= 8;
    }

    if (x >= 0) 
    {
        /* move the result back to BB */
        memcpy(BB, T, length);
        
        /* free the temporary buffer */
        free(T);

        /* this had a carry */
        return 1;
    }

    /* free the temporary buffer */
    free(T);

    /* this didn't carry */
    return 0;
}

/* BB += FF */
void plus_equals_value(unsigned char *BB, 
                     const unsigned char *FF, 
                     const int length)
{
    int ct, tmp;
    int carry = 0;

    for (ct = length - 1; ct >= 0; ct--) 
    {
	    tmp = BB[ct] + FF[ct] + carry;
	    if (tmp >= 256)
	        carry = 1;
	    else
	        carry = 0;
	    BB[ct] = (unsigned char) (tmp);
    }
}

/* L = M * (256**m) mod PublicKey */
void lynx_mont(unsigned char *L,            /* result */
               const unsigned char *M,      /* original chunk of encrypted data */
               const unsigned char *N,      /* copy of encrypted data */
               const unsigned char *modulus,/* modulus */
		       const int length)
{
    int i, j;
    int carry;

    /* L = 0 */
    memset(L, 0, length);

    for(i = 0; i < length; i++)
    {
	    int numA;

        /* get the byte from N */
	    numA = N[i];

        for(j = 0; j < 8; j++) 
        {
            /* L = L * 2 */
	        double_value(L, length);

	        /* carry is true if the MSB in numA is set */
            carry = (numA & 0x80) / 0x80;

            /* multiply numA by 2 */
	        numA = (unsigned char) (numA << 1);
	   
            /* if we're going to carry... */
            if (carry != 0) 
            {
                /* L += M */
		        plus_equals_value(L, M, length);

                /* L -= modulus */
                carry = minus_equals_value(L, modulus, length);

                /* if there is a carry, do it again
                 * L -= modulus 
                 */
                if (carry != 0)
                    minus_equals_value(L, modulus, length);
            } 
            else
            {
                /* L -= modulus */
                minus_equals_value(L, modulus, length);
            }
        }
    }
}


/* this decrypts a single block of encrypted data by using the montgomery
 * multiplication method to do modular exponentiation.
 */
int decrypt_block(int accumulator,
                  unsigned char * result,
                  const unsigned char * encrypted,
                  const unsigned char * public_exp,
                  const unsigned char * public_mod,
                  const int length)
{
    int i;
    unsigned char* rptr = result;
    const unsigned char* eptr = encrypted;
    unsigned char *A;
    unsigned char *B;
    unsigned char *TMP;

    /* allocate the working buffers */
    A = calloc(1, length);
    B = calloc(1, length);
    TMP = calloc(1, length);

    /* this copies the next length sized block of data from the encrypted
     * data into our temporary memory buffer in reverse order */
    for(i = length - 1; i >= 0; i--) 
    {
        B[i] = *eptr;
        eptr++;
    }

    /* so it took me a while to wrap my head around this because I couldn't
     * figure out how the exponent was used in the process.  RSA is 
     * a ^ b (mod c) and I couldn't figure out how that was being done until
     * I realized that the public exponent for decryption is just 3.  That
     * means that to decrypt each block, we only have to multiply each
     * block by itself twice to raise it to the 3rd power:
     * n^3 == n * n * n
     *
     * so this loop is a "per-block" loop and for each block we do the following:
     * 1. make a copy of the block into a temp block
     * 2. multiply the block by the copy in the temp block
     * 3. copy the result into the temp block
     * 4. multiply the block by the accumulated/modulated result in the temp block
     * 5. copy the result into the output block
     */

    /* TODO: convert this to a loop that calls lynx_mont public_exp number of
     * times so that we raise the encrypted block of data to the power of
     * public_exp and mod it by public_mod.
     */

    /* do Montgomery multiplication: A = B^2 */
    lynx_mont(A, B, B, public_mod, length);

    /* copy the result into the temp buffer: TMP = B^2 */
    memcpy(TMP, A, length);

    /* do Montgomery multiplication again: A = B^3 */
    lynx_mont(A, B, TMP, public_mod, length);

    /* So I'm not sure if this is part of the Montgomery multiplication 
     * algorithm since I don't fully understand how that works.  This may be
     * just another obfuscation step done during the encryption process. 
     * The output of the decryption process has to be accumulated and masked
     * to get the original bytes.  If I had to place a bet, I would bet that
     * this is not part of Montgomery multiplication and is just an obfuscation
     * preprocessing step done on the plaintext data before it gets encrypted.
     */
    for(i = length - 1; i > 0; i--)
    {
        accumulator += A[i];
        accumulator &= 0xFF;
        (*rptr) = (unsigned char)(accumulator);
        rptr++;
    }
    
    /* free the temporary buffer memory */
    free(A);
    free(B);
    free(TMP);

    return accumulator;
}


/* this function decrypts a single frame of encrypted data. a frame consists of
 * a single byte block count followed by the count number of blocks of
 * encrypted data.
 */
int decrypt_frame(unsigned char * result, 
                  const unsigned char * encrypted,
                  const unsigned char * public_exp,
                  const unsigned char * public_mod,
                  const int length)
{
    int i, j;
    int blocks;
    int accumulator;
    unsigned char* rptr = result;
    const unsigned char* eptr = encrypted;

    /* reset the accumulator for the modulus step */
    accumulator = 0;

    /* calculate how many encrypted blocks there are */
    blocks = 256 - *eptr;

    /* move our index to the beginning of the next block */
    eptr++;

    for(i = 0; i < blocks; i++)
    {
        /* decrypt a single block of encrypted data */
        accumulator = decrypt_block(accumulator, rptr, eptr, public_exp, public_mod, length);

        /* move result pointer ahead */
        rptr += (length - 1);

        /* move read pointer ahead */
        eptr += length;
    }

    /* return the number of blocks decrypted */
    return blocks;
}

/* this is a completely refactored version of what happens in the Lynx at boot
 * time.  the original code was a very rough reverse of the Lynx ROM code, this
 * is much easier to understand.
 */
void lynx_decrypt(unsigned char * result,
                  const unsigned char * encrypted,
                  const int length)
{
    int blocks = 0;
    int read_index = 0;

    /* decrypt the first frame of encrypted data */
    blocks = decrypt_frame(&result[0],
                           &encrypted[read_index], 
                           /* lynx_public_exp */ 0,
                           lynx_public_mod,
                           length);

    /* adjust the read index */
    read_index = 1 + (blocks * length);

    /* decrypte the second frame of encrypted data */
    blocks = decrypt_frame(&result[256],  
                           &encrypted[read_index], 
                           /* lynx_public_exp */ 0,
                           lynx_public_mod,
                           length);
}

int main(int argc, char *argv[])
{
    int m;
    unsigned char result[600];

    /* clear out the result buffer */
    memset(result, 0, 600);

    /* decrypt harry's encrypted loader */
    lynx_decrypt(result, HarrysEncryptedLoader, CHUNK_LENGTH);

    /* compare the results against the plaintext version */
    if(memcmp(result, HarrysFullPlaintextLoader, 506) == 0)
    	printf("LynxDecrypt works\n");
    else 
	    printf("LynxDecrypt fails\n");

    return 0;
}
