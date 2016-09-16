#include "ecdh_curve25519.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ECDH_KEY_LENGTH crypto_scalarmult_curve25519_BYTES

uint8_t alice_secret_key[ECDH_CURVE25519_KEY_LENGTH];
uint8_t alice_public_key[ECDH_CURVE25519_KEY_LENGTH];

uint8_t bob_secret_key[ECDH_CURVE25519_KEY_LENGTH];
uint8_t bob_public_key[ECDH_CURVE25519_KEY_LENGTH];

uint8_t alice_shared_secret[ECDH_CURVE25519_KEY_LENGTH];
uint8_t bob_shared_secret[ECDH_CURVE25519_KEY_LENGTH];

void binary_to_hexstr(char *str, const uint8_t *binary, unsigned int len)
{
     char *nextchar = str;
     for (unsigned int i = 0; i < len; i++) {
	  nextchar += sprintf(nextchar, "%02X", binary[i]);
     }
}

void create_random_number(uint8_t *random_number, size_t len)
{
     // REPLACE THIS BY A GOOD RANDOM NUMBER GENERATOR FOR PRODUCTIVE SYSTEMS!
     unsigned int count = 0;
     for (int i = 0; i < len; i++) {
	  uint8_t r = (uint8_t) ((double) rand()/RAND_MAX*256.0);
	  random_number[i] = r;
     }
}

int main(int argc, char *argv[])
{
     // First, we do the initial DH key exchange steps for Alice:
     // 1. Create Alice's secret key.
     // 2. Calculate the public key of Alice from her secret key.

     // Create secrete key from big random number.
     uint8_t random_number[ECDH_CURVE25519_KEY_LENGTH];
     create_random_number(random_number, sizeof(random_number));
     ecdh_curve25519_secret_key(alice_secret_key, random_number);
     ecdh_curve25519_public_key(alice_public_key, alice_secret_key);

     // Also Bob is calculating his key-pair.
     create_random_number(random_number, sizeof(random_number));
     ecdh_curve25519_secret_key(bob_secret_key, random_number);
     ecdh_curve25519_public_key(bob_public_key, bob_secret_key);

     // Now Alice and Bob would exchange their public keys.
     // Assume, Alice is now knowing Bob's public key and vice versa.
     
     // Alice calculates the shared_secret from her own secret key and
     // Bob's public key.
     ecdh_curve25519_shared_secret(alice_shared_secret, alice_secret_key, 
				   bob_public_key);

     // Bob also calculates the shared secret.
     ecdh_curve25519_shared_secret(bob_shared_secret, bob_secret_key, 
				   alice_public_key);
     
     // Let's see whether Alice and Bob share the same secret.
     char alice_shared_secret_str[ECDH_CURVE25519_KEY_LENGTH*2 + 1];
     char bob_shared_secret_str[ECDH_CURVE25519_KEY_LENGTH*2 + 1];
     memset(alice_shared_secret_str, 0, sizeof(alice_shared_secret_str));
     memset(bob_shared_secret_str, 0, sizeof(bob_shared_secret_str)); 
     binary_to_hexstr(alice_shared_secret_str, alice_shared_secret, 
		      sizeof(alice_shared_secret));
     binary_to_hexstr(bob_shared_secret_str, bob_shared_secret,  
		      sizeof(bob_shared_secret)); 
	    
     printf("Alice's shared secret:\t%s\nBob's shared secret:\t%s\n", 
	    alice_shared_secret_str, bob_shared_secret_str);
}
