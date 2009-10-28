#include <stdio.h>
#include <string.h>
#include "keys.h"
#include "loaders.h"

/*
  Curt Vendell has posted the encryption sources to AtariAge.
  The encryption sources work by indexing everything with the
  least significant byte first.

  In the real Atari Lynx hardware the byte order is LITTLE_ENDIAN.
  If you run this on Intel or AMD CPU then you also have LITTLE_ENDIAN.
  But the original encryption was run on Amiga that has a BIG_ENDIAN CPU.

  This means that all the keys are presented in BIG_ENDIAN format.
*/

#define CHUNK_LENGTH (51)
#define min(x,y) ((x < y) ? x : y)

/* BB = 2 * BB */
void Double(unsigned char *BB, int m)
{
    int i, x;

    x = 0;
    for (i = m - 1; i >= 0; i--) 
    {
	    x += 2 * BB[i];
	    BB[i] = (unsigned char) (x & 0xFF);
	    x >>= 8;
    }
    /* shouldn't carry */
}

/* BB = (BB - NN) */
int Adjust(unsigned char *BB, const unsigned char *NN, int m)
{
    int i, x;
    unsigned char T[CHUNK_LENGTH];

    x = 0;
    for (i = m - 1; i >= 0; i--) 
    {
	    x += BB[i] - NN[i];
	    T[i] = (unsigned char) (x & 0xFF);
	    x >>= 8;
    }

    if (x >= 0) 
    {
        memcpy(BB, T, m);
        return 1;
    }

    return 0;
}

// BB = BB + FF
void add_it(unsigned char *BB, const unsigned char *FF, int m)
{
    int ct, tmp;
    int carry = 0;

    for (ct = m - 1; ct >= 0; ct--) 
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
void LynxMont(unsigned char *L, /* result */
              const unsigned char *M, /* original chunk of encrypted data */
              const unsigned char *N, /* copy of encrypted data */
              const unsigned char *PublicKey,
		      int m)
{
    int Yctr;
    int carry;

    // L = 0
    memset(L, 0, m);

    Yctr = 0;

    do 
    {
	    int num8, numA;

        // get the first byte from N
	    numA = N[Yctr];
	    num8 = 255;

        do 
        {
            // L = L * 2
	        Double(L, m);

	        // carry is true if the MSB in numA is set
            carry = (numA & 0x80) / 0x80;

            // multiply numA by 2
	        numA = (unsigned char) (numA << 1);
	   
            // if we're going to carry...
            if (carry != 0) 
            {
                // L = L + M
		        add_it(L, M, m);

                // L = L - PublicKey
                carry = Adjust(L, PublicKey, m);

                // if there is a carry, do it again
                // L = L - PublicKey
                if (carry != 0)
                    Adjust(L, PublicKey, m);
            } 
            else
            {
                Adjust(L, PublicKey, m);
            }

            // divide num8 by 2
	        num8 = num8 >> 1;
	
          // this loop runs 8 times
        } while (num8 != 0);
	
        Yctr++;
    
    } while (Yctr < m);
}

void print_data(const unsigned char * data, int size)
{
    int i = 0;
    int j, count;
    int left = size;

    while(i < size)
    {
        count = min(8, (size - i));

        for(j = 0; j < count; j++)
        {
            printf("0x%02x, ", data[i + j]);
        }
        printf("\n");
        i += count;
    }
}

int convert_it(int result_index, int read_index, 
               unsigned char * result, 
               const unsigned char * encrypted,
               const unsigned char * public_key)
{
    int i;
    int tmp_val;
    int accumulator;
    unsigned char A[CHUNK_LENGTH];
    unsigned char B[CHUNK_LENGTH];
    unsigned char TMP[CHUNK_LENGTH];

    /* clear out the memory buffers */
    memset(A, 0, CHUNK_LENGTH);
    memset(B, 0, CHUNK_LENGTH);
    memset(TMP, 0, CHUNK_LENGTH);

    printf("reading %d from index: %d\n", encrypted[read_index], read_index);

    accumulator = 0;
    tmp_val = encrypted[read_index];
    read_index++;

    do 
    {
        /* this copies the next CHUNK_LENGTH block of data from the encrypted
         * data into our temporary memory buffer in reverse order */
        for(i = CHUNK_LENGTH - 1; i >= 0; i--) 
        {
	        B[i] = encrypted[read_index];
	        read_index++;
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
        
        
        // copy E to F
        memcpy(TMP, B, CHUNK_LENGTH);

        // do Montgomery multiplication
        LynxMont(A, B, TMP, public_key, CHUNK_LENGTH);

        // copy B to F
        memcpy(TMP, A, CHUNK_LENGTH);

        // do Montgomery multiplication again
        LynxMont(A, B, TMP, public_key, CHUNK_LENGTH);

        /* I'm not sure what this does...I can see that it is copying the results
         * data to the output results buffer but I don't know why it is doing an
         * accumulation and masking...maybe this is the modulus operation of
         * Montgomery multiplication.
         */
        for(i = CHUNK_LENGTH - 1; i > 0; i--)
        {
            accumulator += A[i];
            accumulator &= 0xFF;
            result[result_index] = (unsigned char)(accumulator);
            result_index++;
        }
        
        tmp_val++;
    
    } while (tmp_val != 256);

    return read_index;
}

// This is what really happens inside the Atari Lynx at boot time
void LynxDecrypt(const unsigned char * encrypted,
                 unsigned char * result)
{
    int read_index;

    read_index = convert_it(0, 0, result, 
                            encrypted, LynxPublicKey);

    read_index = convert_it(256, read_index, result, 
                            encrypted, LynxPublicKey);
}

int main(int argc, char *argv[])
{
    int m;
    unsigned char result[600];

    /* clear out the result buffer */
    memset(result, 0, 600);

    /* decrypt harry's encrypted loader */
    LynxDecrypt(HarrysEncryptedLoader, result);

    /* compare the results against the plaintext version */
    if(memcmp(result, HarrysPlaintextLoader, LOADER_LENGTH) == 0)
    	printf("LynxDecrypt works\n");
    else 
	    printf("LynxDecrypt fails\n");

    return 0;
}
