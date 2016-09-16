/**
 * This file is part of ECDH-Curve25519-Mobile.
 *
 * Written in 2016 by Frank Duerr.
 * Based on avrnacl by Michael Hutter and Peter Schwabe.
 *
 * To the extent possible under law, the author(s) have dedicated all 
 * copyright and related and neighboring rights to this software to the 
 * public domain worldwide. This software is distributed without any warranty.
 * You should have received a copy of the CC0 Public Domain Dedication along 
 * with this software. If not, see 
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "ecdh_curve25519.h"
#include "avrnacl.h"
#include <string.h>

void ecdh_curve25519_secret_key(
     uint8_t secret_key[ECDH_CURVE25519_KEY_LENGTH],
     const uint8_t random[ECDH_CURVE25519_KEY_LENGTH])
{
     memcpy(secret_key, random, sizeof(secret_key));

     // We need to clear bits 0-2 and set bit 254 to prevent small-subgroup 
     // attacks and timing attacks, respectively:
     // http://crypto.stackexchange.com/questions/12425/why-are-the-lower-3-bits-of-curve25519-ed25519-secret-keys-cleared-during-creati/12614)
     secret_key[0] &= 248;
     secret_key[ECDH_CURVE25519_KEY_LENGTH-1] &= 127;
     secret_key[ECDH_CURVE25519_KEY_LENGTH-1] |= 64;
}

void ecdh_curve25519_public_key(
     uint8_t public_key[ECDH_CURVE25519_KEY_LENGTH], 
     const uint8_t secret_key[ECDH_CURVE25519_KEY_LENGTH])
{
     // In the following call, base is 9.
     crypto_scalarmult_curve25519_base(public_key, secret_key);
}

void ecdh_curve25519_shared_secret(
     uint8_t shared_secret[ECDH_CURVE25519_KEY_LENGTH],
     const uint8_t my_secret_key[ECDH_CURVE25519_KEY_LENGTH],
     const uint8_t other_public_key[ECDH_CURVE25519_KEY_LENGTH])
{
     crypto_scalarmult_curve25519(shared_secret, my_secret_key, 
				  other_public_key);
}
