package com.codewithaditya.blog.entitiles;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Entity
@Getter
@Setter
public class Role {

    @Id
    private int id;

    private String name;
}
