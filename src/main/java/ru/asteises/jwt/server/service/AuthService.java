package ru.asteises.jwt.server.service;

import io.jsonwebtoken.Claims;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import ru.asteises.jwt.server.auth.JwtRequest;
import ru.asteises.jwt.server.auth.JwtResponse;
import ru.asteises.jwt.server.domain.JwtAuthentication;
import ru.asteises.jwt.server.model.User;

import javax.security.auth.message.AuthException;
import java.util.HashMap;
import java.util.Map;

/**
 * Создадим отдельный сервис AuthService,
 * который также будет отвечать за получение новых access и refresh токенов взамен протухающим.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserService userService;

    // TODO Для хранения рефреш токена используется HashMap лишь для упрощения примера.
    //  Лучше использовать какое-нибудь постоянное хранилище, например Redis.
    private final Map<String, String> refreshStorage = new HashMap<>();

    /*
    Зачем сохранять токены?

    Сохранять их не обязательно, но это дает некоторые преимущества. Если каким-то образом злоумышленник заполучит
    секретный ключ для генерации refresh токенов, он не сможет создавать токены. Потому что ему нужно будет знать время
    создания токена конкретным пользователем.

    Если бы сохранения не было, то он бы мог сгенерировать любой токен для любого пользователя, получить по нему
    access токены, и творить беспредел в системе.

    Но учтите, если у вас есть сайт и мобильное приложение, то вам нужно будет сохранять два refresh токена для одного
    пользователя. По одному на каждого клиента API.

    Еще один плюс, вы можете забанить пользователя в системе и отозвать его refresh токен, реализовав удаление токена
    из хранилища сохраненных и запрет на выдачу новых забаненым пользователям. В другом случае пользователь смог бы
    выпускать себе новые access токены, пока не протух бы refresh токен.
     */

    private final JwtProvider jwtProvider;

    public JwtResponse login(@NonNull JwtRequest authRequest) throws AuthException {

        // находим пользователя по логину;
        final User user = userService.getByLogin(authRequest.getLogin())
                .orElseThrow(() -> new AuthException("Пользователь не найден"));

        // сверяем присланный пароль с паролем пользователя;
        if (user.getPassword().equals(authRequest.getPassword())) {

            // передаем объект пользователя в JwtProvider и получаем от него токены;
            final String accessToken = jwtProvider.generateAccessToken(user);
            final String refreshToken = jwtProvider.generateRefreshToken(user);

            // сохраняем выданный рефреш токен в мапу;
            refreshStorage.put(user.getLogin(), refreshToken);

            // возвращаем объект JwtResponse с токенами;
            return new JwtResponse(accessToken, refreshToken);
        } else {
            throw new AuthException("Неправильный пароль");
        }
    }

    /**
     * Принимает refresh токен, а возвращает новый access токен
     * <p>
     *
     * @param refreshToken
     * @return
     * @throws AuthException
     */
    public JwtResponse getAccessToken(@NonNull String refreshToken) throws AuthException {

        // проверяем, что присланный rehresh токен валиден;
        if (jwtProvider.validateRefreshToken(refreshToken)) {

            // получаем claims и оттуда получаем логин пользователя;
            final Claims claims = jwtProvider.getRefreshClaims(refreshToken);
            // TODO Login это firstname получается?
            final String login = claims.getSubject();

            // по логину находим выданный пользователю refresh токен в мапе refreshStorage;
            final String saveRefreshToken = refreshStorage.get(login);

            // сверяем refresh токен с присланным пользователем;
            if (saveRefreshToken != null && saveRefreshToken.equals(refreshToken)) {
                final User user = userService.getByLogin(login)
                        .orElseThrow(() -> new AuthException("Пользователь не найден"));

                // получаем новый access токен, без обновления refresh токена;
                final String accessToken = jwtProvider.generateAccessToken(user);
                return new JwtResponse(accessToken, null);
            }
        }
        return new JwtResponse(null, null);
    }

    public JwtResponse refresh(@NonNull String refreshToken) throws AuthException {
        if (jwtProvider.validateRefreshToken(refreshToken)) {
            final Claims claims = jwtProvider.getRefreshClaims(refreshToken);
            final String login = claims.getSubject();
            final String saveRefreshToken = refreshStorage.get(login);
            if (saveRefreshToken != null && saveRefreshToken.equals(refreshToken)) {
                final User user = userService.getByLogin(login)
                        .orElseThrow(() -> new AuthException("Пользователь не найден"));
                final String accessToken = jwtProvider.generateAccessToken(user);
                final String newRefreshToken = jwtProvider.generateRefreshToken(user);
                refreshStorage.put(user.getLogin(), newRefreshToken);
                return new JwtResponse(accessToken, newRefreshToken);
            }
        }
        throw new AuthException("Невалидный JWT токен");
    }

    public JwtAuthentication getAuthInfo() {
        return (JwtAuthentication) SecurityContextHolder.getContext().getAuthentication();
    }

}
