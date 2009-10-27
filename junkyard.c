/* this file contains cruft from the main file that is not needed
 * for decryption. */


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


