package com.codewithaditya.blog.repositories;

import com.codewithaditya.blog.entitiles.Role;
import org.springframework.data.jpa.repository.JpaRepository;


public interface RoleRepo extends JpaRepository<Role, Integer> {
}
