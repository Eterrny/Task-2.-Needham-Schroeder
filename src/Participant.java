import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.util.Random;

public class Participant {
    private final String name;
    private BigInteger randomInt;
    private SecretKey key, sessionKey;

    public String getName() {
        return name;
    }

    public BigInteger getRandomInt() {
        return randomInt;
    }

    public SecretKey getSessionKey() {
        return sessionKey;
    }

    public SecretKey getKey() {
        return key;
    }

    public void setSessionKey(SecretKey sessionKey) {
        this.sessionKey = sessionKey;
    }

    public Participant(String name, SecretKey key) {
        this.name = name;
        this.key = key;
        this.generateRandomInt();
    }

    private void generateRandomInt() {
        Random rand = new Random();
        this.randomInt = new BigInteger(32, rand);
    }
}
