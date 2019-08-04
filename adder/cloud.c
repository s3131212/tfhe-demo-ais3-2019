#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>

int main() {
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    const TFheGateBootstrappingParameterSet* params = bk->params;

    LweSample* ca = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* cb = new_gate_bootstrapping_ciphertext_array(16, params);

    FILE* cloud_data = fopen("cloud.data","rb");
    for (int i=0; i<16; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ca[i], params);
    for (int i=0; i<16; i++)
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &cb[i], params);
    fclose(cloud_data);

    printf("===============server===============\n");

    LweSample* result = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* Carry = new_gate_bootstrapping_ciphertext_array(17, params);
    time_t start_time = clock();
    bootsXOR(&result[0], &ca[0], &cb[0], bk);
    bootsAND(&Carry[0], &ca[0],&cb[0], bk);
    for (int i=1; i<16; i++){
        bootsAND(&Carry[i], &ca[i], &cb[i], bk);
	    bootsXOR(&result[i], &ca[i], &cb[i], bk);
	    bootsAND(&Carry[i+1], &result[i], &Carry[i-1], bk);
	    bootsOR(&Carry[i], &Carry[i], &Carry[i+1], bk);
	    bootsXOR(&result[i], &result[i], &Carry[i-1], bk);
    }

    time_t end_time = clock();
    
    printf("computation time: %f microsecs\n\n\n\n", (double)(end_time-start_time) / (double)1000000);

    FILE* answer_data = fopen("answer.data","wb");
    for (int i=0; i<16; i++)
        export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], params);
    fclose(answer_data);

    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(16, result);
    delete_gate_bootstrapping_ciphertext_array(16, Carry);
    delete_gate_bootstrapping_ciphertext_array(15, ca);
    delete_gate_bootstrapping_ciphertext_array(15, cb);
    delete_gate_bootstrapping_cloud_keyset(bk);
}
