/**
 * This is free and unencumbered software released into the public domain.
 *
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

package de.frank_durr.ecdhcurve25519test;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import java.security.SecureRandom;

import de.frank_durr.ecdh_curve25519.ECDHCurve25519;

public class MainActivity extends AppCompatActivity {
    public static final String TAG = ECDHCurve25519.class.getName();

    private TextView textViewAliceSharedSecret;
    private TextView textViewBobSharedSecret;

    static {
        try {
            System.loadLibrary("ecdhcurve25519");
            Log.i(TAG, "Loaded ecdhcurve25519 library.");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, e.getMessage());
        }
    }

    static private String binarytoHexString(byte[] binary)
    {
        StringBuilder sb = new StringBuilder(binary.length*2);

        // Go backwards (left to right in the string) since typically you print the low-order
        // bytes to the right.
        for (int i = binary.length-1; i >= 0; i--) {
            // High nibble first, i.e., to the left.
            // Note that bytes are signed in Java. However, "int x = abyte&0xff" will always
            // return an int value of x between 0 and 255.
            // "int v = binary[i]>>4" (without &0xff) does *not* work.
            int v = (binary[i]&0xff)>>4;
            char c;
            if (v < 10) {
                c = (char) ('0'+v);
            } else {
                c = (char) ('a'+v-10);
            }
            sb.append(c);
            // low nibble
            v = binary[i]&0x0f;
            if (v < 10) {
                c = (char) ('0'+v);
            } else {
                c = (char) ('a'+v-10);
            }
            sb.append(c);
        }

        return sb.toString();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
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

                // Display both shared secrets to check visually that they are actually the same.

                String alice_shared_secret_str = binarytoHexString(alice_shared_secret);
                String bob_shared_secret_str = binarytoHexString(bob_shared_secret);
                textViewAliceSharedSecret.setText(alice_shared_secret_str);
                textViewBobSharedSecret.setText(bob_shared_secret_str);
            }
        });

        textViewAliceSharedSecret = (TextView) findViewById(R.id.alice_secret);
        textViewBobSharedSecret = (TextView) findViewById(R.id.bob_secret);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
