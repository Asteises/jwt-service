package ru.asteises.jwt.server.enums;

import org.springframework.security.core.GrantedAuthority;

public enum Roles implements GrantedAuthority {

    ADMIN("ADMIN"),
    USER("USER");

    private final String value;

    Roles(String value) {
        this.value = value;
    }

    @Override
    public String getAuthority() {
        return value;
    }
}
