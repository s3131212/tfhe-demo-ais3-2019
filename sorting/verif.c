#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>


int main() {
    //reads the cloud key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

    //read the 16 ciphertexts of the result
    LweSample* answer[5];
    FILE* answer_data = fopen("answer.data","rb");
    for (int i = 0; i < 5; i++) {
        answer[i] = new_gate_bootstrapping_ciphertext_array(16, params);
        for (int j = 0; j < 16; j++)
            import_gate_bootstrapping_ciphertext_fromFile(answer_data, &answer[i][j], params);
    }
    fclose(answer_data);
    printf("===============client===============\n");
    printf("Server says that the result is: ");
    //decrypt and rebuild the answer
    uint16_t int_answer;
    for(int i = 0; i < 5; i++){
        int_answer = 0;
        for (int j = 0; j < 16; j++) {
            int ai = bootsSymDecrypt(&answer[i][j], key) > 0;
            int_answer |= (ai<<j);
        }
        printf("%hu%c", int_answer, " \n"[i==5-1]);
    }
    printf("\n\n\n\n");

    //clean up all pointers
    for(int i = 0; i < 5; i++)
        delete_gate_bootstrapping_ciphertext_array(16, answer[i]);
    delete_gate_bootstrapping_secret_keyset(key);
}
