package com.codewithaditya.blog.services;

import com.codewithaditya.blog.payloads.PostDto;
import com.codewithaditya.blog.payloads.PostResponse;

import java.util.List;

public interface PostService {

    //create post
    PostDto createPost(PostDto postDto, Integer userId, Integer categoryId);

    //read by id
    PostDto getPostById(Integer postId);

    //read all
    PostResponse getAllPosts(Integer pageNumber, Integer pageSize, String sortBy, String sortDir);

    //update
    PostDto updatePost(PostDto postDto, Integer postId);

    //delete
    void deletePost(Integer postId);

    //get all posts by category
    PostResponse getPostsByCategory(Integer categoryId, Integer pageNumber, Integer pageSize, String sortBy, String sortDir);

    //get posts by user
    PostResponse getPostByUser(Integer userId, Integer pageNumber, Integer pageSize, String sortBy, String sortDir);

    //search posts by keyword - title
    List<PostDto> searchPosts(String keyword);
}
