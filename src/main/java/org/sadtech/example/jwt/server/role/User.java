package org.sadtech.example.jwt.server.role;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.sadtech.example.jwt.server.enums.Roles;

import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class User {

    private String login;
    private String password;
    private String firstName;
    private String lastName;
    private Set<Roles> roles;

}
