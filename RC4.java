import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
 
public class SymmetricCipherRC4 {
 
   public static String encrypt(String plaintext, byte[] key) throws Exception {
       SecretKey secretKey = new SecretKeySpec(key, "RC4");
       Cipher cipher = Cipher.getInstance("RC4");
       cipher.init(Cipher.ENCRYPT_MODE, secretKey);
       byte[] encrypted = cipher.doFinal(plaintext.getBytes());
       return Base64.getEncoder().encodeToString(encrypted);
   }
 
   public static String decrypt(String ciphertextBase64, byte[] key) throws Exception {
       SecretKey secretKey = new SecretKeySpec(key, "RC4");
       Cipher cipher = Cipher.getInstance("RC4");
       cipher.init(Cipher.DECRYPT_MODE, secretKey);
       byte[] ciphertext = Base64.getDecoder().decode(ciphertextBase64);
       byte[] decrypted = cipher.doFinal(ciphertext);
       return new String(decrypted);
   }
 
   public static void main(String[] args) throws Exception {
       String message = "Hello, this is a secret message!";
       byte[] key = "secretkey1234567".getBytes();  // RC4 key (length can vary, but 16 bytes is common)
 
       String encrypted = encrypt(message, key);
       System.out.println("Encrypted (RC4): " + encrypted);
 
       String decrypted = decrypt(encrypted, key);
       System.out.println("Decrypted (RC4): " + decrypted);
   }
}
