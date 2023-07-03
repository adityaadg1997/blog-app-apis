package com.codewithaditya.blog.services.impl;

import com.codewithaditya.blog.entitiles.Comment;
import com.codewithaditya.blog.entitiles.Post;
import com.codewithaditya.blog.entitiles.User;
import com.codewithaditya.blog.exceptions.ResourceNotFoundException;
import com.codewithaditya.blog.payloads.CommentDto;
import com.codewithaditya.blog.repositories.CommentRepo;
import com.codewithaditya.blog.repositories.PostRepo;
import com.codewithaditya.blog.repositories.UserRepo;
import com.codewithaditya.blog.services.CommentService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CommentServiceImpl implements CommentService {

    @Autowired
    private PostRepo postRepo;

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private CommentRepo commentRepo;

    @Autowired
    private ModelMapper modelMapper;


    @Override
    public CommentDto createComment(Integer userId, Integer postId, CommentDto commentDto) {

        Post post = this.postRepo.findById(postId).orElseThrow(() -> new ResourceNotFoundException("Post", "postId", postId));
        User user = this.userRepo.findById(userId).orElseThrow(() -> new ResourceNotFoundException("User", "userId", userId));


        Comment comment = this.modelMapper.map(commentDto, Comment.class);
        comment.setPost(post);
        comment.setUser(user);
        Comment savedComment = this.commentRepo.save(comment);

        return this.modelMapper.map(savedComment, CommentDto.class);
    }

    @Override
    public void deleteComment(Integer commentId) {
        this.commentRepo.deleteById(commentId);
    }
}
