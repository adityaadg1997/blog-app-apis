package com.codewithaditya.blog.repositories;

import com.codewithaditya.blog.entitiles.Category;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CategoryRepo extends JpaRepository<Category, Integer> {
}
