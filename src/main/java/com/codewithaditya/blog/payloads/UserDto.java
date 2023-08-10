package com.codewithaditya.blog.payloads;

import com.codewithaditya.blog.entitiles.Role;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
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

    @NotEmpty(message = "Email is Required")
    @Email(message = "Email address is not valid !!")
    private String email;

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @NotEmpty
    @Size(min = 3, message = "Pasword must contain 3 to 10 characters !!")
    private String password;

    @NotEmpty(message="must not be empty")
    private String about;

    Set<RoleDto> roles = new HashSet<>();
}
