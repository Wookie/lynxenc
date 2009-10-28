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

int convert_it(int result_index, int read_index, 
               unsigned char * result, 
               const unsigned char * encrypted,
               const unsigned char * public_key)
{
    int ct;
    int tmp_val;
    int tmp_cnt;
    unsigned char B[CHUNK_LENGTH];
    unsigned char E[CHUNK_LENGTH];
    unsigned char F[CHUNK_LENGTH];

    memset(B, 0, CHUNK_LENGTH);
    memset(E, 0, CHUNK_LENGTH);
    memset(F, 0, CHUNK_LENGTH);

    tmp_val = encrypted[read_index];
    tmp_cnt = 0;
    read_index++;

    do 
    {
    	int Yctr = 0x32;

	    for (ct = CHUNK_LENGTH - 1; ct >= 0; ct--) 
        {
	        E[ct] = encrypted[read_index];
	        read_index++;
	    }

        // copy E to F
        memcpy(F, E, CHUNK_LENGTH);

        // do Montgomery multiplication
        LynxMont(B, E, F, public_key, CHUNK_LENGTH);

        // copy B to F
        memcpy(F, B, CHUNK_LENGTH);

        // do Montgomery multiplication again
        LynxMont(B, E, F, public_key, CHUNK_LENGTH);

        do 
        {
	        tmp_cnt += B[Yctr];
	        tmp_cnt &= 255;
	        result[result_index] = (unsigned char) (tmp_cnt);
	        result_index++;
	        Yctr--;
	    } while (Yctr != 0);

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
    printf("read_index: %d\n", read_index);

    read_index = convert_it(256, read_index, result, 
                            encrypted, LynxPublicKey);
    printf("read_index: %d\n", read_index);
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
