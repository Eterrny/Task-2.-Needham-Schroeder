import junit.framework.TestCase;
import org.junit.Assert;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ServerTest extends TestCase {
    public void testEncryptDecrypt() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String input = "baeldung";
        SecretKey key = Server.generateKey(128);
        IvParameterSpec ivParameterSpec = Server.generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";
        String cipherText = Server.encrypt(algorithm, input, key, ivParameterSpec);
        String plainText = Server.decrypt(algorithm, cipherText, key, ivParameterSpec);
        Assert.assertEquals(input, plainText);
    }

    public void testConversion() throws NoSuchAlgorithmException {
        SecretKey encodedKey = Server.generateKey(128);
        String encodedString = Server.convertSecretKeyToString(encodedKey);
        SecretKey decodeKey = Server.convertStringToSecretKeyto(encodedString);
        Assert.assertEquals(encodedKey, decodeKey);
    }
}