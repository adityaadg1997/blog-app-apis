package com.codewithaditya.blog.repositories;

import com.codewithaditya.blog.entitiles.Comment;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CommentRepo extends JpaRepository<Comment, Integer> {
}
