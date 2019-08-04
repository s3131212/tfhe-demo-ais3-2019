#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define R_MAX 10000

int main() {
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    srand(time(0));
    uint32_t seed[] = { rand()%R_MAX, rand()%R_MAX, rand()%R_MAX };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    uint16_t plaintext[2];
    printf("===============client===============\n");
    printf("input 2 numer: ");
    scanf("%hu%hu", plaintext, plaintext+1);
    printf("Received: %hu %hu, sending to cloud\n\n\n\n", plaintext[0], plaintext[1]);

    LweSample* ciphertext[] = {
        new_gate_bootstrapping_ciphertext_array(16, params),
        new_gate_bootstrapping_ciphertext_array(16, params)
    };
    for (int i=0; i<16; i++)
        bootsSymEncrypt(&ciphertext[0][i], (plaintext[0]>>i)&1, key);
    for (int i=0; i<16; i++)
        bootsSymEncrypt(&ciphertext[1][i], (plaintext[1]>>i)&1, key);

    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    FILE* cloud_data = fopen("cloud.data","wb");
    for (int i=0; i<16; i++)
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[0][i], params);
    for (int i=0; i<16; i++)
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[1][i], params);
    fclose(cloud_data);

    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext[0]);
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext[1]);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
}
