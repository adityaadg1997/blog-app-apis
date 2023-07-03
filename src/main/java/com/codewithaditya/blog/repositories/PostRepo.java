package com.codewithaditya.blog.repositories;

import com.codewithaditya.blog.entitiles.Category;
import com.codewithaditya.blog.entitiles.Post;
import com.codewithaditya.blog.entitiles.User;
import com.codewithaditya.blog.payloads.PostDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PostRepo extends JpaRepository<Post, Integer> {

    Page<Post> findByCategory(Pageable pageable, Category category);
    Page<Post> findByUser(Pageable pageable, User user);

    List<Post> findByTitleContaining(String title);
}
