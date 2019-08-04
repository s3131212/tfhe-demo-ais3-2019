#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define R_MAX 10000

int main() {
    //generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    srand(time(0));
    uint32_t seed[] = { rand()%R_MAX, rand()%R_MAX, rand()%R_MAX };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);
    printf("===============client===============\n");
    // input
    const uint16_t size = 5;
    // printf("typing array size: ");
    // scanf("%hu", &size);
    uint16_t *plaintext = malloc(size*sizeof(uint16_t));
    printf("input %hu numer: ", size);
    for (uint16_t i = 0; i < size; i++)
        scanf("%hu", plaintext+i);

    //generate encrypt the 16 bits of number
    LweSample* ciphertext[5];
    for (uint16_t i = 0; i < size; i++) {
        ciphertext[i] = new_gate_bootstrapping_ciphertext_array(16, params);
        for (uint16_t j = 0; j < 16; j++)
            bootsSymEncrypt(&ciphertext[i][j], plaintext[i]&(1<<j), key);
    }

    printf("Storing ciphertext of ");
    for (uint16_t i = 0; i < size; i++)
        printf("%hu%c", plaintext[i], " \n"[i==size-1]);
    printf("\n\n\n");
    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    //export the 32 ciphertexts to a file (for the cloud)
    FILE* cloud_data = fopen("cloud.data","wb");
    for (int32_t i = 0; i < size; i++) {
        for (int32_t j = 0; j < 16; j++)
            export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[i][j], params);
    }
    fclose(cloud_data);
    for (int32_t i = 0; i < size; i++) {
        delete_gate_bootstrapping_ciphertext_array(16, ciphertext[i]);
    }

    //clean up all pointers
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
}
