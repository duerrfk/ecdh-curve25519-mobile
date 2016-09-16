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

#include "de_frank_durr_ecdh_curve25519_ECDHCurve25519.h"
#include "ecdh_curve25519.h"

JNIEXPORT jbyteArray JNICALL Java_de_frank_1durr_ecdh_1curve25519_ECDHCurve25519_secret_1key
  (JNIEnv *env, jclass ecdhcurve25519_jclass, jbyteArray random_number_jobj)
{
     // We assume that the array random_number_jobj has length
     // ECDH_CURVE25519_KEY_LENGTH. This should be checked on the Java side
     // before calling this native function.
     uint8_t random_number[ECDH_CURVE25519_KEY_LENGTH];
     // jbyte is actually a signed char. So we can safely typecast (uint8_t *) 
     // to (jbyte *).
     env->GetByteArrayRegion(random_number_jobj, 0, ECDH_CURVE25519_KEY_LENGTH,
			     (jbyte *) random_number);
     
     uint8_t secret_key[ECDH_CURVE25519_KEY_LENGTH];
     ecdh_curve25519_secret_key(secret_key, random_number);

     jbyteArray secret_key_jobj = env->NewByteArray(ECDH_CURVE25519_KEY_LENGTH);
     env->SetByteArrayRegion(secret_key_jobj, 0, ECDH_CURVE25519_KEY_LENGTH, 
			     (jbyte *) secret_key);
     
     return secret_key_jobj;
}

JNIEXPORT jbyteArray JNICALL Java_de_frank_1durr_ecdh_1curve25519_ECDHCurve25519_public_1key
  (JNIEnv *env, jclass ecdhcurve25519_jclass, jbyteArray secret_key_jobj)
{
     // We assume that the array secret_key_jobj has length
     // ECDH_CURVE25519_KEY_LENGTH. This should be checked on the Java side
     // before calling this native function.
     uint8_t secret_key[ECDH_CURVE25519_KEY_LENGTH];
     // jbyte is actually a signed char. So we can safely typecast (uint8_t *)
     // to (jbyte *).
     env->GetByteArrayRegion(secret_key_jobj, 0, ECDH_CURVE25519_KEY_LENGTH,
			     (jbyte *) secret_key);
     
     uint8_t public_key[ECDH_CURVE25519_KEY_LENGTH];
     ecdh_curve25519_public_key(public_key, secret_key);

     jbyteArray public_key_jobj = env->NewByteArray(ECDH_CURVE25519_KEY_LENGTH);
     env->SetByteArrayRegion(public_key_jobj, 0, ECDH_CURVE25519_KEY_LENGTH, 
			     (jbyte *) public_key);
     
     return public_key_jobj;
}

JNIEXPORT jbyteArray JNICALL Java_de_frank_1durr_ecdh_1curve25519_ECDHCurve25519_shared_1secret
  (JNIEnv *env, jclass ecdhcurve25519_jclass, jbyteArray my_secret_key_jobj, 
   jbyteArray others_public_key_jobj)
{
     // We assume that the arrays my_secret_key_jobj and 
     // others_public_key_jobj have length ECDH_CURVE25519_KEY_LENGTH. 
     // This should be checked on the Java side before calling this native 
     // function.
     uint8_t my_secret_key[ECDH_CURVE25519_KEY_LENGTH];
     uint8_t others_public_key[ECDH_CURVE25519_KEY_LENGTH];
     // jbyte is actually a signed char. So we can safely typecast (uint8_t *) 
     // to (jbyte *).
     env->GetByteArrayRegion(my_secret_key_jobj, 0, ECDH_CURVE25519_KEY_LENGTH,
			     (jbyte *) my_secret_key);
     env->GetByteArrayRegion(others_public_key_jobj, 0, 
			     ECDH_CURVE25519_KEY_LENGTH, 
			     (jbyte *) others_public_key);
     
     uint8_t shared_secret[ECDH_CURVE25519_KEY_LENGTH];
     ecdh_curve25519_shared_secret(shared_secret, my_secret_key,
				   others_public_key);

     jbyteArray shared_secret_jobj = env->NewByteArray(
	  ECDH_CURVE25519_KEY_LENGTH);
     env->SetByteArrayRegion(shared_secret_jobj, 0, ECDH_CURVE25519_KEY_LENGTH, 
			     (jbyte *) shared_secret);
     
     return shared_secret_jobj;
}

