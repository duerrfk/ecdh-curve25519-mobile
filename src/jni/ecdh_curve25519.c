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
