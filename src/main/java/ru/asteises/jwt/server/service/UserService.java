package ru.asteises.jwt.server.service;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import ru.asteises.jwt.server.enums.Roles;
import ru.asteises.jwt.server.role.User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final List<User> users;

    public UserService() {
        this.users = List.of(
                new User("anton", "1234", "Антон", "Иванов", Collections.singleton(Roles.USER)),
                new User("ivan", "12345", "Сергей", "Петров", Collections.singleton(Roles.USER))
        );
    }

    public Optional<User> getByLogin(@NonNull String login) {
        return users.stream()
                .filter(user -> login.equals(user.getLogin()))
                .findFirst();
    }

}
