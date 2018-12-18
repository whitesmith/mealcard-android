package co.whitesmith.mealcard

import android.annotation.TargetApi
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal

class SecureEncryption(
        private val context: Context,
        val keyAlias: String,
        private var sharedPreferences: SharedPreferences? = null) {

    companion object {
        const val TAG = "SecureEncryption"

        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val AES_MODE = "AES/GCM/NoPadding"
        val FIXED_IV = "0jz/9ozl9RGJMWgU+LECelJYvdhpA0cSi/vWkqOKOV8=".toByteArray()

        // Legacy: pre-M (before API level 23)
        private val RSA_PROVIDER = "AndroidOpenSSL"
        private val RSA_MODE = "RSA/ECB/PKCS1Padding"
        private val RSA_ALGORITHM = "RSA"
        private val SHARED_PREFENCE_NAME = "SecureEncryptionPreferences"
        private val AES_ENCRYPTED_KEY = "AES"
        private val AES_PKCS7Padding_MODE = "AES/ECB/PKCS7Padding"
    }

    private val keyStore: KeyStore
    private val preferences: SharedPreferences

    // Legacy: pre-M (before API level 23)
    private val rsaStartDate: Calendar
    private val rsaEndDate: Calendar

    init {
        keyStore = createKeyStore()

        rsaStartDate = Calendar.getInstance()
        rsaEndDate = Calendar.getInstance()
        rsaEndDate.add(Calendar.YEAR, 10)

        if (sharedPreferences == null) {
            sharedPreferences = context.getSharedPreferences(SHARED_PREFENCE_NAME, Context.MODE_PRIVATE)
        }
        preferences = sharedPreferences!!
    }

    /**
     * This encrypts the input for the api version after and before M (API level 23).
     * This method takes in the input which is to be encrypted.
     * Then the key generated above is retrieved from the key store.
     * The input is encrypted to cipher text using this key which is then returned finally.
     */
    fun encrypt(value: String): String {
        val bytes = value.toByteArray(Charsets.UTF_8)
        val cipher = getCipher(Cipher.ENCRYPT_MODE)
        val encodedBytes = cipher.doFinal(bytes)
        return Base64.encodeToString(encodedBytes, Base64.DEFAULT)
    }

    /**
     * This decrypts the input for the api version after and before M (API level 23).
     * This method takes in the input which is to be decrypted.
     * Then the key generated above is retrieved from the key store.
     * The input is decrypted to plain text using this key which is then returned finally.
     */
    fun decrypt(value: String): String {
        val decode = Base64.decode(value, Base64.DEFAULT)
        val cipher = getCipher(Cipher.DECRYPT_MODE)
        val decodedBytes = cipher.doFinal(decode)
        return String(decodedBytes, Charsets.UTF_8)
    }

    private fun getCipher(operationMode: Int): Cipher {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val cipher = Cipher.getInstance(AES_MODE)
            val secretKey = keyStore.getKey(keyAlias, null)
            try {
                cipher.init(operationMode, secretKey, GCMParameterSpec(128, FIXED_IV))
                return cipher
            }
            catch (e: InvalidKeyException) {
                keyStore.deleteEntry(keyAlias)
                generateAliasKey()
                return getCipher(operationMode)
            }
        }
        else {
            val cipher = Cipher.getInstance(AES_PKCS7Padding_MODE, "BC")
            val secretKey = getSecretKey()
            cipher.init(operationMode, secretKey)
            return cipher
        }
    }

    private fun createKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null) //null is ok for AndroidKeyStore

        if (!keyStore.containsAlias(keyAlias)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                generateAliasKey()
            }
            else {
                val generator = KeyPairGenerator.getInstance(RSA_ALGORITHM, ANDROID_KEY_STORE)
                generator.initialize(getSpecFromKeyPairGenerator())
                generator.generateKeyPair()
                generateAESKey()
            }
        }

        return keyStore
    }

    @TargetApi(Build.VERSION_CODES.M)
    private fun generateAliasKey() {
        val keyPairGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        keyPairGenerator.init(getSpecFromKeyGenParameter())
        keyPairGenerator.generateKey()
    }

    /**
     * It uses KeyGenParameterSpec API which is included only for API levels 23 and higher.
     * This method generates a key if already a key with the same name is not generated by the keystore.
     * The keystore in this case uses AES algorithm mode of encryption.
     * This is a symmetric mode of encryption i.e it uses same key both for encryption and decryption.
     */
    @TargetApi(Build.VERSION_CODES.M)
    private fun getSpecFromKeyGenParameter() =
            KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(false)
                    .build()

    /**
     * Legacy: Pre-M
     * This handles for the API version before M (API level 23).
     */

    @Suppress("DEPRECATION")
    private fun getSpecFromKeyPairGenerator() =
            KeyPairGeneratorSpec.Builder(context)
                    .setAlias(keyAlias)
                    .setSubject(X500Principal("CN=" + keyAlias))
                    .setSerialNumber(BigInteger.TEN)
                    .setStartDate(rsaStartDate.time)
                    .setEndDate(rsaEndDate.time)
                    .build()

    @Throws(Exception::class)
    private fun rsaEncrypt(secret: ByteArray): ByteArray {
        val privateKeyEntry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry

        val inputCipher = Cipher.getInstance(RSA_MODE, RSA_PROVIDER)
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.certificate.publicKey)

        val outputStream = ByteArrayOutputStream()
        val cipherOutputStream = CipherOutputStream(outputStream, inputCipher)
        cipherOutputStream.write(secret)
        cipherOutputStream.close()

        return outputStream.toByteArray()
    }

    @Throws(Exception::class)
    private fun rsaDecrypt(encrypted: ByteArray): ByteArray {
        val privateKeyEntry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry

        val output = Cipher.getInstance(RSA_MODE, RSA_PROVIDER)
        output.init(Cipher.DECRYPT_MODE, privateKeyEntry.privateKey)
        val cipherInputStream = CipherInputStream(ByteArrayInputStream(encrypted), output)

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

    @Throws(Exception::class)
    private fun generateAESKey(): String {
        var enryptedKeyB64 = preferences.getString(AES_ENCRYPTED_KEY, null)
        if (enryptedKeyB64 == null) {
            val key = ByteArray(16)
            val secureRandom = SecureRandom()
            secureRandom.nextBytes(key)

            val encryptedKey = rsaEncrypt(key)
            enryptedKeyB64 = Base64.encodeToString(encryptedKey, Base64.DEFAULT)

            val edit = preferences.edit()
            edit.putString(AES_ENCRYPTED_KEY, enryptedKeyB64)
            edit.apply()
        }
        return enryptedKeyB64
    }

    @Throws(Exception::class)
    private fun getSecretKey(): Key {
        var enryptedKeyB64 = preferences.getString(AES_ENCRYPTED_KEY, null)
        if (enryptedKeyB64 == null) {
            enryptedKeyB64 = generateAESKey()
        }
        val encryptedKey = Base64.decode(enryptedKeyB64, Base64.DEFAULT)
        val key = rsaDecrypt(encryptedKey)
        return SecretKeySpec(key, "AES")
    }

}