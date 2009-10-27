/* this file contains cruft from the main file that is not needed
 * for decryption. */

unsigned char A[CHUNK_LENGTH];
unsigned char InputData[CHUNK_LENGTH];
unsigned char C[CHUNK_LENGTH];
unsigned char PrivateKey[CHUNK_LENGTH];
unsigned char PublicKey[CHUNK_LENGTH];
unsigned char AtariPrivateKey[CHUNK_LENGTH];
unsigned char Result[410];
int ptr;
int Xctr;

#define bool char
#define false 0
#define true 1

#define BIT(C, i, m) ((C)[(i)/8] & (1 << (7 - ((i) & 7))))

void WriteOperand(FILE * fp, const unsigned char *A, int m)
{
    int i;
    unsigned char byte;

    for (i = 0; i < m; i++) 
    {
	    byte = A[i];
	    fprintf(fp, "%02x", byte);
    }
    fprintf(fp, "\n");
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

/* A = 1 */
void One(unsigned char *A, int m)
{
    memset(A, 0, m);
    A[m - 1] = 1;
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

/* A = B */
void Copy(unsigned char *A, unsigned char *B, int m)
{
    int i;

    for (i = 0; i < m; i++)
	    A[i] = B[i];
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

    memcpy(A, B, m);

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

    memset(T, 0, 2 * m);

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


