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

int c;
int num2;
int num7;
int ptr5;
int Cptr;
int Actr;
int carry;
int err;
int ptrEncrypted;

unsigned char buffer[600];
unsigned char result[600];
unsigned char B[CHUNK_LENGTH];
unsigned char E[CHUNK_LENGTH];
unsigned char F[CHUNK_LENGTH];

/* B = 2*B */
void Double(unsigned char *B, int m)
{
    int i, x;

    x = 0;
    for (i = m - 1; i >= 0; i--) 
    {
	    x += 2 * B[i];
	    B[i] = (unsigned char) (x & 0xFF);
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
void add_it(unsigned char *BB, unsigned char *FF, int m)
{
    int ct, tmp;
    carry = 0;
    for (ct = m - 1; ct >= 0; ct--) 
    {
	    tmp = BB[ct] + FF[ct] + carry;
	    if (tmp >= 256)
	        carry = 1;
	    else
	        carry = 0;
	    B[ct] = (unsigned char) (tmp);
    }
}

/* A = B*(256**m) mod PublicKey */
void LynxMont(unsigned char *L, /* result */
                     unsigned char *M, /* original chunk of encrypted data */
                     unsigned char *N, /* copy of encrypted data */
                     const unsigned char *PublicKey,
		             int m)
{
    int Yctr;

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

void sub5000(int m)
{
    // copy E to F
    memcpy(F, E, m);

    // do Montgomery multiplication
    LynxMont(B, E, F, LynxPublicKey, m);

    // copy B to F
    memcpy(F, B, m);

    // do Montgomery multiplication
    LynxMont(B, E, F, LynxPublicKey, m);
}

void convert_it()
{
    int ct;
    long t1, t2;

    num7 = buffer[Cptr];
    num2 = 0;
    Cptr++;

    do 
    {
    	int Yctr;

	    for (ct = CHUNK_LENGTH - 1; ct >= 0; ct--) 
        {
	        E[ct] = buffer[Cptr];
	        Cptr++;
	    }
	
        if ((E[0] | E[1] | E[2]) == 0) 
        {
	        err = 1;
	    }
	
        t1 = ((long) (E[0]) << 16) +
	         ((long) (E[1]) << 8) +
	          (long) (E[2]);
	
        t2 = ((long) (LynxPublicKey[0]) << 16) +
	         ((long) (LynxPublicKey[1]) << 8) + 
              (long) (LynxPublicKey[2]);
	
        if (t1 > t2) 
        {
	        err = 1;
	    }

	    sub5000(CHUNK_LENGTH);
	
        if(B[0] != 0x15) 
        {
	        err = 1;
	    }
	
        Actr = num2;
	    Yctr = 0x32;
	
        do 
        {
	        Actr += B[Yctr];
	        Actr &= 255;
	        result[ptr5] = (unsigned char) (Actr);
	        ptr5++;
	        Yctr--;
	    } while (Yctr != 0);

	    num2 = Actr;
	    num7++;
    
    } while (num7 != 256);
    
    if (Actr != 0) {
	    err = 1;
    }
}

// This is what really happens inside the Atari Lynx at boot time
void LynxDecrypt(const unsigned char encrypted_data[])
{
    int i;

    ptrEncrypted = 0xAA;
    c = LOADER_LENGTH;
    
    // this copies the encrypted loader into the buffer
    for (i = 0; i < c; i++) 
    {
	    buffer[i] = encrypted_data[i];
    }

    ptr5 = 0;
    Cptr = 0;
    
    convert_it();
    
    ptr5 = 256;
    
    convert_it();
}

int main(int argc, char *argv[])
{
    int m;

    /* decrypt harry's encrypted loader */
    LynxDecrypt(HarrysEncryptedLoader);

    /* compare the results against the plaintext version */
    if(memcmp(result, HarrysPlaintextLoader, LOADER_LENGTH) == 0)
    	printf("LynxDecrypt works\n");
    else 
	    printf("LynxDecrypt fails\n");

    return 0;
}
