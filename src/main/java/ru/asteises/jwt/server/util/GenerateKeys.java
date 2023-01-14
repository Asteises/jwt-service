package ru.asteises.jwt.server.util;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

/**
 * Как получить ключи?
 *
 * Самым надежным способом будет воспользоваться методом Keys.secretKeyFor(), который генерирует надежные ключи,
 * но он возвращает объект SecretKey.
 * Нам же нужно как-то получить текстовую строку, чтобы использовать ее в application.properties.
 *
 * Для этого можно получить массив байт ключа, используя метод SecretKey.getEncoded(), и преобразовать их в Base64.
 * Этот механизм я описал в классе GenerateKeys. Можно просто запустить этот класс и получить два ключа.
 *
 * Обратите внимание на конструктор JwtProvider, там происходит обратный процесс.
 * Мы преобразуем Base64 обратно в массив байт, после чего используем Keys.hmacShaKeyFor(),
 * чтобы восстановить из этих байтов объект ключа SecretKey.
 */
public class GenerateKeys {

    public static void main(String[] args) {
        System.out.println(generateKey());
        System.out.println(generateKey());
    }

    private static String generateKey() {
        return Encoders.BASE64.encode(Keys.secretKeyFor(SignatureAlgorithm.HS512).getEncoded());
    }
}
