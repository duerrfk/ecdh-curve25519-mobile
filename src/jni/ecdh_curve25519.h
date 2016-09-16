/**
 * This file is part of ECDH-Curve25519-Mobile.
 *
 * Written in 2016 by Frank Duerr.
 * Based on avrnacl by Michael Hutter and Peter Schwabe.
 *
 * This is free and unencumbered software released into the public domain.
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 * 
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 * 
 * For more information, please refer to <http://unlicense.org/>
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
