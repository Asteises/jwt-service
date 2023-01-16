package ru.asteises.jwt.server.exeption;

/**
 * Исключение, которое используется для ошибок аутентификации и авторизации.
 */
public class AuthException extends RuntimeException {

    public AuthException(String message) {
        super(message);
    }

}
