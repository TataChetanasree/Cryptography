import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.security.SecureRandom;

public class SymmetricCipherAES {

    // Generate AES key (128-bit)
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 128-bit AES
        return keyGen.generateKey();
    }

    // Generate random IV (16 bytes for AES)
    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String encrypt(String plaintext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        // Prepend IV to ciphertext for easy storage/transmission
        byte[] ivAndCiphertext = new byte[iv.getIV().length + encrypted.length];
        System.arraycopy(iv.getIV(), 0, ivAndCiphertext, 0, iv.getIV().length);
        System.arraycopy(encrypted, 0, ivAndCiphertext, iv.getIV().length, encrypted.length);
        return Base64.getEncoder().encodeToString(ivAndCiphertext);
    }

    public static String decrypt(String ivAndCiphertextBase64, SecretKey key) throws Exception {
        byte[] ivAndCiphertext = Base64.getDecoder().decode(ivAndCiphertextBase64);
        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[ivAndCiphertext.length - 16];
        System.arraycopy(ivAndCiphertext, 0, iv, 0, 16);
        System.arraycopy(ivAndCiphertext, 16, ciphertext, 0, ciphertext.length);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {
        String message = "Hello, this is a secret message!";
        SecretKey key = generateAESKey();
        IvParameterSpec iv = generateIV();

        String encrypted = encrypt(message, key, iv);
        System.out.println("Encrypted (AES): " + encrypted);

        String decrypted = decrypt(encrypted, key);
        System.out.println("Decrypted (AES): " + decrypted);
    }
}
