package co.whitesmith.mealcard

import android.content.Context
import android.os.Build
import android.os.Bundle
import android.support.design.widget.FloatingActionButton
import android.support.design.widget.Snackbar
import android.support.v7.app.AppCompatActivity
import android.support.v7.widget.Toolbar
import android.util.Base64
import android.util.Log
import android.view.View
import android.view.Menu
import android.view.MenuItem
import javax.crypto.KeyGenerator
import android.security.KeyPairGeneratorSpec
import java.math.BigInteger
import java.util.*
import javax.security.auth.x500.X500Principal
import android.security.keystore.KeyProperties
import android.security.keystore.KeyGenParameterSpec
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.*
import java.security.interfaces.RSAPrivateKey
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec


class MainActivity : AppCompatActivity() {

    private val TAG = "MainActivity"

    private val AndroidKeyStore = "AndroidKeyStore"
    private val AES_MODE = "AES/GCM/NoPadding"
    private val KEY_ALIAS = "Optimize"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val toolbar = findViewById<View>(R.id.toolbar) as Toolbar
        setSupportActionBar(toolbar)

        val fab = findViewById<View>(R.id.fab) as FloatingActionButton
        fab.setOnClickListener { view ->
            // Generate a new key
            //val keyGenerator = KeyGenerator.getInstance("AES")
            //keyGenerator.init(512)
            //val secretKey = keyGenerator.generateKey()
            //val secretKeyEncoded = secretKey.encoded
            //Log.i(TAG, "Example AES-512 random key: " + Util.bytesToHex(key))

            val keyStore: KeyStore = KeyStore.getInstance(AndroidKeyStore)
            keyStore.load(null)

            val aliases = keyStore.aliases()
            for (alias in aliases) {
                Log.i("KeyStore Alias", alias)
            }

            val input = "OMG, this is working!"
            val FIXED_IV = "fixed_direct".toByteArray()

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (!keyStore.containsAlias(KEY_ALIAS)) {
                    // Generating the key
                    val keyPairGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, AndroidKeyStore)
                    keyPairGenerator.init(
                            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                    .setRandomizedEncryptionRequired(false)
                                    .build()
                    )
                    keyPairGenerator.generateKey()
                }

                val secretKey = keyStore.getKey(KEY_ALIAS, null)
                //AndroidKeyStoreRSAPrivateKey

                val cipher = Cipher.getInstance(AES_MODE)

                // Encrypt
                try {
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, FIXED_IV))
                }
                catch (e: InvalidKeyException) {
                    // Delete alias
                    Log.i(TAG, e.localizedMessage)
                    keyStore.deleteEntry(KEY_ALIAS)

                    // Repeat
                    if (!keyStore.containsAlias(KEY_ALIAS)) {
                        // Generating the key
                        val keyPairGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, AndroidKeyStore)
                        keyPairGenerator.init(
                                KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                        .setRandomizedEncryptionRequired(false)
                                        .build()
                        )
                        keyPairGenerator.generateKey()
                    }

                    val secretKey = keyStore.getKey(KEY_ALIAS, null)

                    //AndroidKeyStoreRSAPrivateKey

                    val cipher = Cipher.getInstance(AES_MODE)

                    cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, FIXED_IV))

                    val encodedBytes = cipher.doFinal(input.toByteArray())
                    Log.i(TAG, "Encrypted: " + Base64.encodeToString(encodedBytes, Base64.DEFAULT))
                    val encrypted = Base64.encodeToString(encodedBytes, Base64.DEFAULT)

                    // Decrypt
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, FIXED_IV))
                    val decode = Base64.decode(encrypted, Base64.DEFAULT)
                    val decodedBytes = cipher.doFinal(decode)
                    Log.i(TAG, "Decrypted: " + String(decodedBytes, Charsets.UTF_8))

                    return@setOnClickListener
                }

                val encodedBytes = cipher.doFinal(input.toByteArray())
                Log.i(TAG, "Encrypted: " + Base64.encodeToString(encodedBytes, Base64.DEFAULT))
                val encrypted = Base64.encodeToString(encodedBytes, Base64.DEFAULT)

                // Decrypt
                cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, FIXED_IV))
                val decode = Base64.decode(encrypted, Base64.DEFAULT)
                val decodedBytes = cipher.doFinal(decode)
                Log.i(TAG, "Decrypted: " + String(decodedBytes, Charsets.UTF_8))
            }
            else {
                if (!keyStore.containsAlias(KEY_ALIAS)) {
                    val start = Calendar.getInstance()
                    val end = Calendar.getInstance()
                    end.add(Calendar.YEAR, 1)

                    val spec = KeyPairGeneratorSpec.Builder(this)
                            .setAlias(KEY_ALIAS)
                            .setSubject(X500Principal("CN=" + KEY_ALIAS))
                            .setSerialNumber(BigInteger.TEN)
                            .setStartDate(start.time)
                            .setEndDate(end.time)
                            .build()

                    val generator = KeyPairGenerator.getInstance("RSA", AndroidKeyStore)
                    generator.initialize(spec)
                    generator.generateKeyPair()
                }

                generateAESKey(this, keyStore)
                val encrypted = encrypt(this, input.toByteArray(), keyStore)
                Log.i(TAG, "Encrypted: " + encrypted)

                val decode = Base64.decode(encrypted, Base64.DEFAULT)
                val decodedBytes = decrypt(this, decode, keyStore)
                Log.i(TAG, "Decrypted: " + String(decodedBytes, Charsets.UTF_8))
            }

            Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                    .setAction("Action", null).show()
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        val id = item.itemId

        return if (id == R.id.action_settings) {
            true
        } else super.onOptionsItemSelected(item)
    }

    // RSA Encryption and Decryption Routines
    private val RSA_MODE = "RSA/ECB/PKCS1Padding"

    @Throws(Exception::class)
    private fun rsaEncrypt(keyStore: KeyStore, secret: ByteArray): ByteArray {
        val privateKeyEntry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        // Encrypt the text
        val inputCipher = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL")
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.certificate.publicKey)

        val outputStream = ByteArrayOutputStream()
        val cipherOutputStream = CipherOutputStream(outputStream, inputCipher)
        cipherOutputStream.write(secret)
        cipherOutputStream.close()

        return outputStream.toByteArray()
    }

    @Throws(Exception::class)
    private fun rsaDecrypt(keyStore: KeyStore, encrypted: ByteArray): ByteArray {
        val privateKeyEntry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        val output = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL")
        output.init(Cipher.DECRYPT_MODE, privateKeyEntry.privateKey)
        val cipherInputStream = CipherInputStream(
                ByteArrayInputStream(encrypted), output)
        val values = ArrayList<Byte>()

        while (true) {
            val nextByte = cipherInputStream.read()
            if (nextByte == -1) break
            values.add(nextByte.toByte())
        }

        val bytes = ByteArray(values.size)
        for (i in bytes.indices) {
            bytes[i] = values.get(i)
        }
        return bytes
    }

    // Generate and Store the AES Key
    private val SHARED_PREFENCE_NAME = "Preferences"
    private val ENCRYPTED_KEY = "Security"

    @Throws(Exception::class)
    private fun generateAESKey(context: Context, keyStore: KeyStore) {
        val pref = context.getSharedPreferences(SHARED_PREFENCE_NAME, Context.MODE_PRIVATE)
        var enryptedKeyB64 = pref.getString(ENCRYPTED_KEY, null)
        if (enryptedKeyB64 == null) {
            val key = ByteArray(16)
            val secureRandom = SecureRandom()
            secureRandom.nextBytes(key)

            val encryptedKey = rsaEncrypt(keyStore, key)
            enryptedKeyB64 = Base64.encodeToString(encryptedKey, Base64.DEFAULT)

            val edit = pref.edit()
            edit.putString(ENCRYPTED_KEY, enryptedKeyB64)
            edit.apply()
        }
    }

    private val AES_PKCS7Padding_MODE = "AES/ECB/PKCS7Padding"

    // Encrypting the Data
    @Throws(Exception::class)
    private fun getSecretKey(context: Context, keyStore: KeyStore): Key {
        val pref = context.getSharedPreferences(SHARED_PREFENCE_NAME, Context.MODE_PRIVATE)
        val enryptedKeyB64 = pref.getString(ENCRYPTED_KEY, null)
        // need to check null, omitted here
        val encryptedKey = Base64.decode(enryptedKeyB64, Base64.DEFAULT)
        val key = rsaDecrypt(keyStore, encryptedKey)
        return SecretKeySpec(key, "AES")
    }

    @Suppress("DEPRECATION")
    fun encrypt(context: Context, input: ByteArray, keyStore: KeyStore): String {
        val c = Cipher.getInstance(AES_PKCS7Padding_MODE, "BC")
        c.init(Cipher.ENCRYPT_MODE, getSecretKey(context, keyStore))
        val encodedBytes = c.doFinal(input)
        return Base64.encodeToString(encodedBytes, Base64.DEFAULT)
    }

    @Suppress("DEPRECATION")
    fun decrypt(context: Context, encrypted: ByteArray, keyStore: KeyStore): ByteArray {
        val c = Cipher.getInstance(AES_PKCS7Padding_MODE, "BC")
        c.init(Cipher.DECRYPT_MODE, getSecretKey(context, keyStore))
        return c.doFinal(encrypted)
    }
}
