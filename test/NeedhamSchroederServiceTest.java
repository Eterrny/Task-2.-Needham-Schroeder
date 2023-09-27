import junit.framework.TestCase;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class NeedhamSchroederServiceTest extends TestCase {
    public void testProtocolExceptionKey() {
        java.security.InvalidParameterException thrown = assertThrows(
                java.security.InvalidParameterException.class,
                () -> new NeedhamSchroederService(100),
                "Ожидалось исключение в new NeedhamSchroederService(100), но его не было."
        );
        assertTrue(thrown.getMessage().contains("Wrong keysize"));
    }

    public void testProtocol() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        NeedhamSchroederService service = new NeedhamSchroederService(128);
        assertEquals(service.getAlice().getSessionKey(), service.getBob().getSessionKey());
    }
}