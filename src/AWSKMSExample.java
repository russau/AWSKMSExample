import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class AWSKMSExample {

    public static void main(String[] args) throws java.lang.Exception {
        AWSKMSClient kms = new AWSKMSClient();
        GenerateDataKeyRequest request = new GenerateDataKeyRequest()
                .withKeyId("e4b5bfe5-37ed-45ae-839a-9b5d3a06d276")
                .withKeySpec("AES_128");

        // Ask KMS for a data key
        GenerateDataKeyResult dataKeyResult = kms.generateDataKey(request);
        ByteBuffer plainTextKey = dataKeyResult.getPlaintext();
        ByteBuffer encryptedKey = dataKeyResult.getCiphertextBlob();
        System.out.println("Plaintext key:");
        System.out.println(Base64.getEncoder().encodeToString(plainTextKey.array()));

        // Encrypt something locally with our data key
        String plaintext = "hello hello hello";
        byte[] data = plaintext.getBytes("UTF-8");
        Key key = new SecretKeySpec(plainTextKey.array(), "AES");

        // Create a random initialization vector
        SecureRandom random = new SecureRandom();
        byte iv[] = new byte[16];
        random.nextBytes(iv);
        System.out.println("Initialization Vector:");
        System.out.println(Base64.getEncoder().encodeToString(iv));

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(data);
        String encryptedBase64 = java.util.Base64.getEncoder().encodeToString(encrypted);
        System.out.println("Encrypted:");
        System.out.println(encryptedBase64);

        // Ask KMS to decrypt our data key
        DecryptRequest decryptRequest = new DecryptRequest().withCiphertextBlob(encryptedKey);
        DecryptResult decrypt = kms.decrypt(decryptRequest);
        String decryptedKey = Base64.getEncoder().encodeToString(decrypt.getPlaintext().array());
        System.out.println("Decrypted Key:");
        System.out.println(decryptedKey);

        // Decrypt with the key we received from KMS
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(encrypted);
        System.out.println("Decrypted!");
        System.out.println(new String(decrypted, "UTF-8"));
    }
}
