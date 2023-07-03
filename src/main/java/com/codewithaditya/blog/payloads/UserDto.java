package com.codewithaditya.blog.payloads;

import com.codewithaditya.blog.entitiles.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
public class UserDto {

    private int id;

    @NotEmpty
    @Size(min = 4, message = "Username must be min of 4 chars !!")
    private String name;

    @Email(message = "Email address is not valid !!")
    private String email;

/*    @JsonIgnore - to hide password*/
    @NotEmpty
    @Size(min = 3, message = "Pasword must contain 3 to 10 characters !!")
    private String password;

    @NotEmpty
    private String about;

    Set<RoleDto> roles = new HashSet<>();
}
