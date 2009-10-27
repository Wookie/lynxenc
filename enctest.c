#include <stdio.h>
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
#define bool char
#define false 0
#define true 1
#define BIT(C, i, m) ((C)[(i)/8] & (1 << (7 - ((i) & 7))))

int ptr, c,
    num2, num7,
    ptr5, Cptr, Actr, Xctr, carry, err, ptrEncrypted;
unsigned char buffer[600];
unsigned char result[600];
unsigned char A[CHUNK_LENGTH];
unsigned char B[CHUNK_LENGTH];
unsigned char InputData[CHUNK_LENGTH];
unsigned char C[CHUNK_LENGTH];
unsigned char PrivateKey[CHUNK_LENGTH];
unsigned char E[CHUNK_LENGTH];
unsigned char F[CHUNK_LENGTH];
unsigned char PublicKey[CHUNK_LENGTH];
unsigned char AtariPrivateKey[CHUNK_LENGTH];
unsigned char Result[410];


void WriteOperand(FILE * fp, const unsigned char *A, int m)
{
    int i;
    unsigned char byte;

    for (i = 0; i < m; i++) {
	byte = A[i];
	fprintf(fp, "%02x", byte);
    }
    fprintf(fp, "\n");
}

/* A = 0 */
void Clear(unsigned char *A, int m)
{
    int i;

    for (i = 0; i < m; i++)
    {
	    A[i] = 0;
    }
}

/* A = 1 */
void One(unsigned char *A, int m)
{
    Clear(A, m);
    A[m - 1] = 1;
}

/* A = B */
void Copy(unsigned char *A, unsigned char *B, int m)
{
    int i;

    for (i = 0; i < m; i++)
	A[i] = B[i];
}

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
	    Copy(BB, T, m);
        return 1;
    }

    return 0;
}

/* v = -1/PublicKey mod 256 */
void MontCoeff(unsigned char *v, unsigned char *PublicKey, int m)
{
    int i;
    int lsb = m - 1;

    *v = 0;
    for (i = 0; i < 8; i++)
	if (!((PublicKey[lsb] * (*v) & (1 << i))))
	    *v += (1 << i);
}

/* A = B*(256**m) mod PublicKey */
void Mont(unsigned char *A, unsigned char *B, unsigned char *PublicKey, int m)
{
    int i;

    Copy(A, B, m);

    for (i = 0; i < 8 * m; i++) {
	Double(A, m);
	Adjust(A, PublicKey, m);
    }
}

/* A = B*C/(256**m) mod PublicKey where v*PublicKey = -1 mod 256 */
void MontMult(unsigned char *A, unsigned char *B, unsigned char *C,
		     unsigned char *PublicKey, unsigned char v, int m)
{
    int i, j;
    unsigned char ei, T[2 * CHUNK_LENGTH];
    unsigned int x;

    Clear(T, 2 * m);

    for (i = m - 1; i >= 0; i--) {
	x = 0;
	for (j = m - 1; j >= 0; j--) {
	    x += (unsigned int) T[i + j] +
		(unsigned int) B[i] * (unsigned int) C[j];
	    T[i + j] = (unsigned char) (x & 0xFF);
	    x >>= 8;
	}
	T[i] = (unsigned char) (x & 0xFF);
    }

    for (i = m - 1; i >= 0; i--) {
	x = 0;
	ei = (unsigned char) (((unsigned int) v * (unsigned int) T[m + i]) &
			      0xFF);
	for (j = m - 1; j >= 0; j--) {
	    x += (unsigned int) T[i + j] +
		(unsigned int) ei *(unsigned int) PublicKey[j];
	    T[i + j] = (unsigned char) (x & 0xFF);
	    x >>= 8;
	}
	A[i] = (unsigned char) (x & 0xFF);
    }

    x = 0;
    for (i = m - 1; i >= 0; i--) {
	x += (unsigned int) T[i] + (unsigned int) A[i];
	A[i] = (unsigned char) (x & 0xFF);
	x >>= 8;
    }
    /* shouldn't carry */
}

/* A = (B**PrivateKey)/(256**((PrivateKey-1)*m)) mod PublicKey, where v*PublicKey = -1 mod 256 */
void MontExp(unsigned char *A, unsigned char *B, unsigned char *PrivateKey,
		    unsigned char *PublicKey, unsigned char v, int m)
{
    int i;
    unsigned char T[CHUNK_LENGTH];

    One(T, m);
    Mont(T, T, PublicKey, m);

    for (i = 0; i < 8 * m; i++) {
	MontMult(T, T, T, PublicKey, v, m);
	if (BIT(PrivateKey, i, m))
	    MontMult(T, T, B, PublicKey, v, m);
    }

    Copy(A, T, m);
}

/* A = B/(256**m) mod PublicKey, where v*PublicKey = -1 mod 256 */
void UnMont(unsigned char *A, unsigned char *B, unsigned char *PublicKey,
		   unsigned char v, int m)
{
    unsigned char T[CHUNK_LENGTH];

    One(T, m);
    MontMult(A, B, T, PublicKey, v, m);

    Adjust(A, PublicKey, m);
}

/* All operands have least significant byte first. */
/* A = B**PrivateKey mod PublicKey */
void ModExp(unsigned char *A, unsigned char *B, unsigned char *PrivateKey,
	    unsigned char *PublicKey, int m)
{
    unsigned char T[CHUNK_LENGTH], v;

    MontCoeff(&v, PublicKey, m);
    Mont(T, B, PublicKey, m);
    MontExp(T, T, PrivateKey, PublicKey, v, m);
    UnMont(A, T, PublicKey, v, m);
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
    Clear(L, m);

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
    Copy(F, E, m);

    // do Montgomery multiplication
    LynxMont(B, E, F, LynxPublicKey, m);

    // copy B to F
    Copy(F, B, m);

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

void ReadLength(FILE * fp, int *m)
{
    fscanf(fp, "%d", m);
}

void ReadOperand(FILE * fp, unsigned char *A, int m)
{
    int i;
    unsigned int byte;

    for (i = m - 1; i >= 0; i--) {
	fscanf(fp, "%02x", &byte);
	A[i] = (unsigned char) byte;
    }
}

void CopyOperand(unsigned char *A, unsigned char *B, int m, char inverted)
{
    int i, j;

    if (inverted) {
        int j;
        j = 0;
        for (i = m - 1; i >= 0; i--) {
	    B[j++] = A[i];
        }
    } else {
        for (i = 0; i < m; i++) {
	    B[i] = A[i];
        }
    }
}

bool Compare(unsigned char *A, const unsigned char *B, int m)
{
    int i;
    bool res = true;

    for (i = 0; i < m; i++) {
	if (B[i] != A[i])
	    res = false;
    }
    return res;
}


void test(char first[51], char second[51], char third[51], bool inverted)
{
    int m;

    // Now we try to make the same thing work in the Amiga way
    // The first thing we need to do is to decrypt the file again
    // using the provided exponent and public key

    // This is what happens in the Amiga. It will read in the length and 3 keys.
    //ReadLength (stdin, &m);
    m = 51;
    Clear(InputData, m);
    Clear(PrivateKey, m);
    Clear(PublicKey, m);
    Clear(Result, m);

    //ReadOperand (stdin, InputData, m);
    CopyOperand(first, InputData, m, inverted);
    //ReadOperand (stdin, PrivateKey, m);
    CopyOperand(second, PrivateKey, m, inverted);
    //ReadOperand (stdin, PublicKey, m);
    CopyOperand(third, PublicKey, m, inverted);

    ModExp(Result, InputData, PrivateKey, PublicKey, m);

    if (Compare(Result, HarrysPlaintextLoader, 51)) {
	printf("Decrypt works\n");
    } else {
	printf("Decrypt fails\n");
        WriteOperand(stdout, InputData, m);
        WriteOperand(stdout, PrivateKey, m);
        WriteOperand(stdout, PublicKey, m);
        WriteOperand(stdout, Result, m);
        WriteOperand(stdout, HarrysPlaintextLoader, m);
    }
}

/* Computes A = InputData**PrivateKey mod PublicKey.
   (1) Inputs length in bytes of operands.
   (2) Inputs InputData, then PrivateKey, then PublicKey, most significant byte first. Most
       significant bit of most significant byte of PublicKey must be zero.
   (3) Computes A.
   (4) Outputs A, most significant byte first.
 */
int main(int argc, char *argv[])
{
    int m;

    LynxDecrypt(HarrysEncryptedLoader);
    if (Compare(result, HarrysPlaintextLoader, 410)) 
    {
    	printf("LynxDecrypt works\n");
    } 
    else 
    {
	    printf("LynxDecrypt fails\n");
    }

    return 0;
}
