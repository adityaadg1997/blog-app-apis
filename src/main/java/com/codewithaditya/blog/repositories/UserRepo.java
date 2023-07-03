package com.codewithaditya.blog.repositories;

import com.codewithaditya.blog.entitiles.Role;
import com.codewithaditya.blog.entitiles.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepo extends JpaRepository<User, Integer> {

    Optional<User> findByEmail(String email);
}
