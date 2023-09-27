import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        if (args.length == 0) {
            System.out.println("Входные параметры отсутсвуют");
            return;
        }
        if (args[0].equals("/help")) {
            System.out.println("""
                    Программе должен передаваться 1 параметр:
                    \t- длина ключа в битах (128, 192, 256)""");
            return;
        }
        int keyLength;
        try {
            keyLength = Integer.parseInt(args[0]);
        } catch (NumberFormatException e) {
            System.out.println("Некорректное значение длины ключа, должно быть передано число!");
            return;
        }
        if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
            throw new IllegalArgumentException("Некорректный ввод. Допустимая длина ключа: 128, 192, 256");
        }
        NeedhamSchroederService service = new NeedhamSchroederService(keyLength);
    }
}