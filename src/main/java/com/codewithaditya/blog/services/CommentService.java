package com.codewithaditya.blog.services;

import com.codewithaditya.blog.payloads.CommentDto;

public interface CommentService {

    //create
    CommentDto createComment(Integer userId, Integer postId, CommentDto commentDto);

    //delete
    void deleteComment(Integer commentId);
}
