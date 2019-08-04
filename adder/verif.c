#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>

int main() {
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    const TFheGateBootstrappingParameterSet* params = key->params;

    LweSample* answer = new_gate_bootstrapping_ciphertext_array(16, params);

    FILE* answer_data = fopen("answer.data","rb");
    for (int i=0; i<16; i++)
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &answer[i], params);
    fclose(answer_data);

    uint16_t int_answer = 0;
    for (int i=0; i<16; i++) {
        int ai = bootsSymDecrypt(&answer[i], key)>0;
        int_answer |= (ai<<i);
    }
    printf("===============client===============\n");
    printf("Server says that the result is: %d\n\n\n\n", int_answer);

    delete_gate_bootstrapping_ciphertext_array(16, answer);
    delete_gate_bootstrapping_secret_keyset(key);
}
