#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>

// elementary full comparator gate that is used to compare the i-th bit:
//   input: ai and bi the i-th bit of a and b
//          lsb_carry: the result of the comparison on the lowest bits
//   algo: if (a==b) return lsb_carry else return b
void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXNOR(tmp, a, b, bk);
    bootsMUX(result, tmp, lsb_carry, a, bk);
}

// this function compares two multibit words, and puts the max in result
void minimum(LweSample* a, LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    LweSample* mx = new_gate_bootstrapping_ciphertext_array(16, bk->params);
    LweSample* mn = new_gate_bootstrapping_ciphertext_array(16, bk->params);

    //initialize the carry to 0
    bootsCONSTANT(&tmps[0], 0, bk);
    //run the elementary comparator gate n times
    for (int i = 0; i < nb_bits; i++)
        compare_bit(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    //tmps[0] is the result of the comparaison: 0 if a is larger, 1 if b is larger
    //select the max and copy it to the result
    for (int i = 0; i < nb_bits; i++)
        bootsMUX(&mx[i], &tmps[0], &a[i], &b[i], bk);
    for (int i = 0; i < nb_bits; i++)
        bootsMUX(&mn[i], &tmps[0], &b[i], &a[i], bk);

    for (int i = 0; i < nb_bits; i++)
        bootsCOPY(&a[i], &mn[i], bk);
    for (int i = 0; i < nb_bits; i++)
        bootsCOPY(&b[i], &mx[i], bk);

    delete_gate_bootstrapping_ciphertext_array(2, tmps);
    delete_gate_bootstrapping_ciphertext_array(16, mx);
    delete_gate_bootstrapping_ciphertext_array(16, mn);
}

/*
int same(const LweSample* a, const LweSample* b, const int nb_bits) {
    for (int i = 0; i < nb_bits; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}
*/

/*
int ismin(LweSample* a, LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmp = new_gate_bootstrapping_ciphertext(bk->params);
    bootsCONSTANT(tmp, 0, bk);
    for (int i = nb_bits-1; i >= 0; i--) {
        bootsXNOR(tmp, &a[i], &b[i], bk);
        if (!tmp) {
            bootsANDNY(tmp, &a[i], &b[i], bk);
            return !!tmp;
        }
    }
    return 0;
}
*/

int main() {
    printf("===============server===============\n");

    //reads the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    const TFheGateBootstrappingParameterSet* params = bk->params;

    LweSample* ciphertext[5];
    FILE* cloud_data = fopen("cloud.data","rb");
    for (int i = 0; i < 5; i++) {
        ciphertext[i] = new_gate_bootstrapping_ciphertext_array(16, params);
        for (int j = 0; j < 16; j++)
            import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext[i][j], params);
    }
    fclose(cloud_data);

    printf("doing the homomorphic computation...\n");

    time_t start_time = clock();

    int n = 5;
    for (int i = 0; i < n-1; i++) for (int j = 0; j < n-i-1; j++)
        minimum(ciphertext[j], ciphertext[j+1], 16, bk);

    time_t end_time = clock();

    printf("computation of bubble sort took: %f microsecs\n", (double)(end_time-start_time) / (double)1000000);

    //export the 32 ciphertexts to a file (for the cloud)
    FILE* answer_data = fopen("answer.data","wb");
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < 16; j++)
            export_gate_bootstrapping_ciphertext_toFile(answer_data, &ciphertext[i][j], params);
    fclose(answer_data);

    printf("\n\n\n\n");

    for(int i = 0; i < 5; i++)
        delete_gate_bootstrapping_ciphertext_array(16, ciphertext[i]);

    //clean up all pointers
    delete_gate_bootstrapping_cloud_keyset(bk);
}
