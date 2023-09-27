import javax.crypto.*;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class NeedhamSchroederService {
    private final Participant alice, bob;
    private final Server server;

    public Participant getAlice() {
        return alice;
    }

    public Participant getBob() {
        return bob;
    }

    public NeedhamSchroederService(int keyLength) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        this.server = new Server(keyLength);
        this.alice = new Participant("Алиса", this.server.getKeyA());
        this.bob = new Participant("Боб", this.server.getKeyB());
        System.out.println("Инициализированы 2 участника протокола: \n"
                + "\t- Алиса, Ra = " + this.alice.getRandomInt() + "\n"
                + "\t- Боб, Rb = " + this.bob.getRandomInt() + "\n");
        this.runProtocol();
    }

    private void runProtocol() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        System.out.println("Шаг 1. Алиса отправляет Тренту следующее сообщение: \n" + "       "
                + this.alice.getName() + ", "
                + this.bob.getName() +
                ", Ra = " + this.alice.getRandomInt() + "\n");

        String aliceRanomIntEncForA = getEncrypted(this.alice.getRandomInt().toString(), true);
        String bobNameEncForA = getEncrypted(this.bob.getName(), true);
        String sessionKeyEncForA = getEncrypted(Server.convertSecretKeyToString(this.server.getSessionKey()), true);
        String sessionKeyEncForB = getEncrypted(Server.convertSecretKeyToString(this.server.getSessionKey()), false);
        String aliceNameEncForB = getEncrypted(this.bob.getName(), true);
        String encForASessionKeyEncForB = getEncrypted(sessionKeyEncForB, true);
        String encForAAliceNameEncForB = getEncrypted(aliceNameEncForB, true);
        System.out.println("Шаг 2. Трент сгенерировал случайный сеансовый ключ K = "
                + Server.convertSecretKeyToString(this.server.getSessionKey()) + "\n" + "       "
                + "Зашифровал секретным ключом Боба сеансовый ключ и имя Алисы. Получил: " + sessionKeyEncForB + ", " + aliceNameEncForB + "\n" + "       "
                + "Зашифровал секретным ключом Алисы случайное число Алисы Ra, имя Боба, ключ и шифрованное сообщение для Боба ключом Алисы." + "\n" + "       "
                + "Отправляет сообщение Алисе: "
                + aliceRanomIntEncForA + ", "
                + bobNameEncForA + ", "
                + sessionKeyEncForA + ", "
                + encForASessionKeyEncForB + ", "
                + encForAAliceNameEncForB + "\n");

        String decryptedKForA = getDecrypted(sessionKeyEncForA, true);
        this.alice.setSessionKey(Server.convertStringToSecretKeyto(decryptedKForA));
        String decryptedRandomIntForA = getDecrypted(aliceRanomIntEncForA, true);
        if (!this.alice.getRandomInt().equals(new BigInteger(decryptedRandomIntForA))) {
            System.out.println("Протокол завершен на шаге 3, так как Алиса получила некорректный Ra от Трента." +
                    "Изначальный Ra = " + this.alice.getRandomInt() + ", Ra от Трента = " + decryptedRandomIntForA);
            return;
        }
        System.out.print("Шаг 3. Алиса расшифровывает К и получает " + decryptedKForA + "\n" + "       " +
                "Расшифровывает число Ra от Трента и получает " + decryptedRandomIntForA + ", равное ее числу." + "\n" + "       ");
        sessionKeyEncForB = getDecrypted(encForASessionKeyEncForB, true);
        aliceNameEncForB = getDecrypted(encForAAliceNameEncForB, true);
        System.out.println("Алиса посылает Бобу сообщение, зашифрованное Трентом ключом Боба:\n"
                + sessionKeyEncForB + ", " + aliceNameEncForB + "\n");

        String decryptedKForB = getDecrypted(sessionKeyEncForB, false);
        this.bob.setSessionKey(Server.convertStringToSecretKeyto(decryptedKForB));
        String bobRandomIntEncForA = Server.encrypt("AES/CBC/PKCS5Padding", this.bob.getRandomInt().toString(), this.bob.getSessionKey(), this.server.getIv());
        System.out.println("Шаг 4. Боб расшифровывает сообщение и извлекает ключ K = " + decryptedKForB + ".\n" + "       "
                + "Зашифровывает Rb = " + this.bob.getRandomInt() + ".\n" + "       "
                + "Отправляет Алисе следующее сообщение: " + bobRandomIntEncForA + "\n");

        BigInteger decryptedBobInt = new BigInteger(Server.decrypt("AES/CBC/PKCS5Padding", bobRandomIntEncForA, this.alice.getSessionKey(), this.server.getIv()));
        decryptedBobInt = decryptedBobInt.subtract(BigInteger.ONE);
        String encNewBobInt = Server.encrypt("AES/CBC/PKCS5Padding", decryptedBobInt.toString(), this.alice.getSessionKey(), this.server.getIv());
        System.out.println("Шаг 5. Алиса расшифровывает Rb, уменьшает его на 1 и получает " + decryptedBobInt + ".\n" + "       "
                + "Зашифровывает это число отправляет Бобу следующее сообщение: " + encNewBobInt + "\n");

        BigInteger newBobInt = new BigInteger(Server.decrypt("AES/CBC/PKCS5Padding", encNewBobInt, this.bob.getSessionKey(), this.server.getIv()));
        if (this.bob.getRandomInt().subtract(BigInteger.ONE).equals(newBobInt)) {
            System.out.println("Шаг 6. Боб расшифровывает сообщение от Алисы и получает " + newBobInt + ".\n" + "       "
                    + "Боб удостоверился в подлинности сообщения.\n");
            if (!decryptedKForA.equals(decryptedKForB)) {
                System.out.println("Произошла ошибка в работе протоколе, сеансовый ключ у Алисы и Боба не совпадает.");
                return;
            }
            System.out.println("Сеансовый ключ успешно установлен. K = " + Server.convertSecretKeyToString(this.alice.getSessionKey()));
        }
    }

    private String getEncrypted(String info, boolean isAlice) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        if (isAlice) {
            return Server.encrypt("AES/CBC/PKCS5Padding", info, this.alice.getKey(), this.server.getIv());
        } else {
            return Server.encrypt("AES/CBC/PKCS5Padding", info, this.bob.getKey(), this.server.getIv());
        }
    }

    private String getDecrypted(String encInfo, boolean isAlice) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        if (isAlice) {
            return Server.decrypt("AES/CBC/PKCS5Padding", encInfo, this.alice.getKey(), this.server.getIv());
        } else {
            return Server.decrypt("AES/CBC/PKCS5Padding", encInfo, this.bob.getKey(), this.server.getIv());
        }
    }
}
