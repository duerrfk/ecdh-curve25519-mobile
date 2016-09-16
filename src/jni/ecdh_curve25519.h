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

#ifndef ECDH_CURVE25519_H
#define ECDH_CURVE25519_H

#include <stdint.h>

#define ECDH_CURVE25519_KEY_LENGTH 32

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a secret key from a random number.
 *
 * @param secret_key secret key.
 * @parem random big random number.
 */
void ecdh_curve25519_secret_key(
     uint8_t secret_key[ECDH_CURVE25519_KEY_LENGTH],
     const uint8_t random[ECDH_CURVE25519_KEY_LENGTH]);

/**
 * Calculate a public key from a secret key.
 *
 * @param public_key public key (x value of a point on the curve in Little 
 * Endian byte order).
 * @param secret_key the secret key.
 */
void ecdh_curve25519_public_key(
     uint8_t public_key[ECDH_CURVE25519_KEY_LENGTH], 
     const uint8_t secret_key[ECDH_CURVE25519_KEY_LENGTH]);

/**
 * Calculate the shared secret from an entity's secret key and the public key 
 * of the other entity participating in the key exchange.
 *
 * @param shared_secret the shared secret.
 * @param my_secret_key secret key of the entity calculating the shared secret.
 * @param other_public_key the public key of the other entity of the key
 * exchange.
 */
void ecdh_curve25519_shared_secret(
     uint8_t shared_secret[ECDH_CURVE25519_KEY_LENGTH],
     const uint8_t my_secret_key[ECDH_CURVE25519_KEY_LENGTH],
     const uint8_t other_public_key[ECDH_CURVE25519_KEY_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif
