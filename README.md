# What is ECDH-Curve25519-Mobile?

ECDH-Curve25519-Mobile implements Diffie-Hellman key exchange based on the Elliptic Curve 25519 for Android devices.

ECDH-Curve25519-Mobile is based on the NaCl crypto implementation, more specifically [AVRNaCl](http://munacl.cryptojedi.org/atmega.shtml), written by Michael Hutter and Peter Schwabe, who dedicated their implementation to the public domain. ECDH-Curve25519-Mobile follows their example and also dedicates the code to the public domain using The Unlicense (cf. file COPYING). Actually, the core of ECDH-Curve25519-Mobile is NaCl code, and ECDH-Curve25519-Mobile is just a simple JNI (Java Native Interface) wrapper around it to make it accessible from Java on Android devices. So we gratefully acknowledge the work of the NaCl team and their generous dedication of their code to the public domain!

ECDH-Curve25519-Mobile is a native Android library since NaCl is implemented in C rather than Java. However, it can be easily compiled for all Android platforms like ARM or x86, so this is not a practical limitation compared to a Java implementation. The decision to base ECDH-Curve25519-Mobile on NaCl was not so much the performance you can gain from a native implementation (as discussed below, using avrnacl leaves some room for performance improvements), but using an implementation from crypto experts who actually work together with Daniel J. Bernstein, the inventor of Curve 25519.  

# Using ECDH-Curve25519-Mobile in your Android project

ECDH-Curve25519-Mobile is a native Android library accessible via the Java Native Interface (JNI) from Android apps. Both, the compiled and linked native library (*.so file) as well as a JAR file with the Java wrapper calling the native library code are included in the repository in the directories `libs` and `jars`, respectively. So you do not need to compile the library first just to use it. If you still want, instructions for compiling the library are below.

In order to use the native library, follow these steps (tested with Android Studio 2.1):

1. Install the native libary by copying the contents of directory `libs` to your Android Studio project folder `app/src/main/jniLibs`. If the folder `jniLibs` does not exist, create it. The `jniLibs` folder should now contain several directories (`armeabi`, `arm64-v8a`, `x86`, etc.) with the native libraries for different platforms.

2. Install the Java class calling the native library by copying the JAR file `ecdh-curve25519.jar` from folder `jars` to your Android Studio project folder `app/libs`

3. Update your Gradle file `build.gradle` by adding the line `compile files('libs/ecdh-curve25519.jar')` to section `dependencies`.

4. In your main activity, load the native library by adding the following static block to the main activity class:

```
static {
    // Load native library ECDH-Curve25519-Mobile implementing Diffie-Hellman key
    // exchange with elliptic curve 25519.
    try {
        System.loadLibrary("ecdhcurve25519");
        Log.i(TAG, "Loaded ecdhcurve25519 library.");
    } catch (UnsatisfiedLinkError e) {
        Log.e(TAG, "Error loading ecdhcurve25519 library: " + e.getMessage());
    }
}
```

Now you can call the library by calling the public methods from class '''de.frank_durr.ecdh_curve25519.ECDHCurve25519'''. The following simple example should give a good idea on how to use the library for Diffie-Hellman key exchange:

    // Create Alice's secret key from a big random number.
    SecureRandom random = new SecureRandom();
    byte[] alice_secret_key = ECDHCurve25519.generate_secret_key(random);
    // Create Alice's public key.
    byte[] alice_public_key = ECDHCurve25519.generate_public_key(alice_secret_key);

    // Bob is also calculating a key pair.
    byte[] bob_secret_key = ECDHCurve25519.generate_secret_key(random);
    byte[] bob_public_key = ECDHCurve25519.generate_public_key(bob_secret_key);

    // Assume that Alice and Bob have exchanged their public keys.

    // Alice is calculating the shared secret.
    byte[] alice_shared_secret = ECDHCurve25519.generate_shared_secret(
        alice_secret_key, bob_public_key);

    // Bob is also calculating the shared secret.
    byte[] bob_shared_secret = ECDHCurve25519.generate_shared_secret(
        bob_secret_key, alice_public_key);

A complete Android Studio project is included in folder `test`.

# Compiling ECDH-Curve25519-Mobile

Two steps are required to compile ECDH-Curve25519-Mobile: compiling the native library and compiling the Java class calling the native library.

In order to comile the native libary, you need to install the Android [NDK](https://developer.android.com/ndk/index.html) first. 

Then, go to folder `src/jni` and type the following command (note that in order for the NDK to work, all sources must be in a folder named `jni`):

    $ ndk-build

The compile libraries can then be found in direcory `src/libs`.

To compile the Java wrapper, go to folder `src/java` and type:

    $ javac -source 1.7 -target 1.7 de/frank_durr/ecdh_curve25519/ECDHCurve25519.java
    $ jar cf ../../jars/ecdh-curve25519.jar *

This will create a JAR file in folder `jars`.

# Why ECDH-Curve25519-Mobile and no other crypto implementation?

ECDH-Curve25519-Mobile was originally developed to exchange keys between an Android device and an IoT device implementing ECDH with Curve 25519 due to performance reasons (the IoT device just features an ARM Cortex-M0 microcontroller, and a highly optimized ARM version for Curve 25519 existed for this platform). 

We first looked at the popular Bouncy/Spongy Castle crypto implementation, which also seemed to support Curve 25519. However, this implementation is based on the Weierstrass form for elliptic curves rather than the Montgomery form used by Curve 25519 on the IoT device. Instead of converting between both forms, we decided to use a lean and mean implementation suppporting the Montgomery form natively, which also seems to be a more natural choice for Curve 25519.

# Why AVRNaCl rather than standard NaCl?

You might wonder why ECDH-Curve25519-Mobile uses the [AVR implementation](http://munacl.cryptojedi.org/atmega.shtml) of NaCl rather than the [standard NaCl version](https://nacl.cr.yp.t). We wanted to to cut out a minimal standalone Curve25519 implementation targeting only Diffie-Hellman key exchange rather than all the other (great!) features of NaCl. AVRNaCl comes with a plain C implementation based on a very small set of files, which made it very easy to cut out the Curve 25519 implementation by basically copying a few files without modifications, which also gives as a good chance not to break anything by making modifications.

Having said this, AVRNaCl is targeting 8 bit platforms, and it might not be as optimized as theoretically possible for Android devices featuring 32 bit or even 64 bit platforms. It would be nice to integrate standard NaCl code or even the ARM-optimized assembler version of NaCl, but for now AVRNaCl code just works for us, and we hope, it also works for you. 

# License

Similar to the core NaCl code used by ECDH-Curve25519-Mobile, also ECDH-Curve25519-Android is dedicated to the public domain.

For further information, please have a look at the included file COPYING.
