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

package de.frank_durr.ecdh_curve25519;

import java.security.InvalidParameterException;
import java.security.SecureRandom;

/**
 * Diffie-Hellman key exchange based on elliptic curve 25519.
 *
 * Curve 25519 is represented in Montgomery form. All coordinates are represented as
 * byte arrays in Little Endian byte order.
 *
 * Note that many elliptic curve crypto implementations for Java such as Bouncy/Spongy Castle
 * use the Weierstrass form rather than the Montgomery form. Moreover, BigInteger as used by
 * these implementations stores coordinates in BigEndian byte order. So if you need to exchange
 * points with such implementations, you need to transform them first. Of course, you can use
 * the shared secret as is for symmetric encryption (e.g., AES) or authentication (e.g., HMAC)
 * also with these libraries.
 */
public class ECDHCurve25519 {
    
    public static final int KEY_LENGTH = 32;

    /**
     * Generate a random secret key. Note that the secret key is not just a random number,
     * but it is ensured that it fulfills some properties that are required to avoid
     * specific attacks. Therefore, use this function to generate the secret key rather than
     * providing your own random byte array.
     *
     * @param random random number generator (RNG).
     * @return secret key.
     */
    public static byte[] generate_secret_key(SecureRandom random) {
        byte[] random_number = new byte[KEY_LENGTH];
        random.nextBytes(random_number);

        byte[] sec_key = secret_key(random_number);

        return sec_key;
    }

    /**
     * Calculate a public key from a secret key.
     *
     * @param secret_key secret key.
     * @return public key (x value of a point on the curve in Little Endian byte order).
     */
    public static byte[] generate_public_key(byte[] secret_key) {
        if (secret_key.length != KEY_LENGTH) {
            throw new InvalidParameterException("Key length must be " + KEY_LENGTH);
        }

        byte[] pub_key = public_key(secret_key);

        return pub_key;
    }

    /**
     * Calculate the shared secret from an entity's secret key and the public key
     * of the other entity participating in the key exchange.
     *
     * @param my_secret_key secret key of the entity calculating the shared secret.
     * @param other_public_key the public key of the other entity of the key exchange.
     * @return the shared secret
     */
    public static byte[] generate_shared_secret(byte[] my_secret_key, byte[] other_public_key) {
        if (my_secret_key.length != KEY_LENGTH || other_public_key.length != KEY_LENGTH) {
            throw new InvalidParameterException("Key length must be " + KEY_LENGTH);
        }

        byte[] shared_secret = shared_secret(my_secret_key, other_public_key);

        return shared_secret;
    }

    private static native byte[] secret_key(byte[] random_number);

    private static native byte[] public_key(byte[] secret_key);

    private static native byte[] shared_secret(byte[] my_secret_key, byte[] other_public_key);
}
