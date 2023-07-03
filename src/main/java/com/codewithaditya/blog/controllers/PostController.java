package com.codewithaditya.blog.controllers;

import com.codewithaditya.blog.config.AppConstants;
import com.codewithaditya.blog.payloads.ApiResponse;
import com.codewithaditya.blog.payloads.PostDto;
import com.codewithaditya.blog.payloads.PostResponse;
import com.codewithaditya.blog.services.FileService;
import com.codewithaditya.blog.services.PostService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import javafx.geometry.Pos;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

@RestController
@RequestMapping("/api")
public class PostController {

    @Autowired
    private PostService postService;

    @Autowired
    private FileService fileService;

    @Value("${project.image}")
    private String path;

    //create
    @Operation(security = { @SecurityRequirement(name = "bearer-key") })
    @PostMapping("/user/{userId}/category/{categoryId}/posts")
    public ResponseEntity<PostDto> createPost(@Valid @RequestBody PostDto postDto,
                                              @PathVariable("userId") Integer userId,
                                              @PathVariable("categoryId") Integer categoryId){

        PostDto createdPost = this.postService.createPost(postDto, userId, categoryId);

        return new ResponseEntity<>(createdPost, HttpStatus.CREATED);
    }

    //read post by id
    @GetMapping("/posts/{postId}")
    public ResponseEntity<PostDto> getPost(@PathVariable("postId") Integer postId){
        PostDto post = this.postService.getPostById(postId);

        return new ResponseEntity<>(post, HttpStatus.OK);
    }

    //read all
    @GetMapping("/posts")
    public ResponseEntity<PostResponse> getAllPost(@RequestParam(value = "pageNumber", defaultValue = AppConstants.PAGE_NUMBER, required = false) Integer pageNumber,
                                                   @RequestParam(value = "pageSize", defaultValue = AppConstants.PAGE_SIZE, required = false) Integer pageSize,
                                                   @RequestParam(value = "sortBy", defaultValue = AppConstants.SORT_BY, required = false) String sortBy,
                                                   @RequestParam(value = "sortDir", defaultValue = AppConstants.SORT_DIR, required = false) String sortDir){
        PostResponse allPosts = this.postService.getAllPosts(pageNumber, pageSize, sortBy, sortDir);

        return new ResponseEntity<>(allPosts, HttpStatus.OK);
    }

    //update
    @Operation(security = { @SecurityRequirement(name = "bearer-key") })
    @PutMapping("/posts/{postId}")
    public ResponseEntity<PostDto> updatePost(@RequestBody PostDto postDto, @PathVariable("postId") Integer postId){
        PostDto updatedPost = this.postService.updatePost(postDto, postId);

        return new ResponseEntity<>(updatedPost, HttpStatus.ACCEPTED);
    }

    //delete
    @Operation(security = { @SecurityRequirement(name = "bearer-key") })
    @DeleteMapping("/posts/{postId}")
    public ResponseEntity<ApiResponse> deletePost(@PathVariable("postId") Integer postId){
        this.postService.deletePost(postId);

        return new ResponseEntity<>(new ApiResponse("Post with id "+ postId + " is successfully deleted !!", true), HttpStatus.OK);
    }

    //read all posts by categoryId
    @GetMapping("/category/{categoryId}/posts")
    public ResponseEntity<PostResponse> getPostsByCategory(@PathVariable("categoryId"  ) Integer categoryId,
                                                           @RequestParam(value = "pageNumber", defaultValue = AppConstants.PAGE_NUMBER, required = false) Integer pageNumber,
                                                           @RequestParam(value = "pageSize", defaultValue = AppConstants.PAGE_SIZE, required = false) Integer pageSize,
                                                           @RequestParam(value = "sortBy", defaultValue = AppConstants.SORT_BY, required = false) String sortBy,
                                                           @RequestParam(value = "sortDir", defaultValue = AppConstants.SORT_DIR, required = false) String sortDir){
        PostResponse postResponse = this.postService.getPostsByCategory(categoryId, pageNumber, pageSize, sortBy, sortDir);

        return new ResponseEntity<>(postResponse, HttpStatus.OK);
    }

    //read all posts by userId
    @GetMapping("/user/{userId}/posts")
    public ResponseEntity<PostResponse> getPostByUser(@PathVariable("userId") Integer userId,
                                                      @RequestParam(value = "pageNumber", defaultValue = AppConstants.PAGE_NUMBER, required = false) Integer pageNumber,
                                                      @RequestParam(value = "pageSize", defaultValue = AppConstants.PAGE_SIZE, required = false) Integer pageSize,
                                                      @RequestParam(value = "sortBy", defaultValue = AppConstants.SORT_BY, required = false) String sortBy,
                                                      @RequestParam(value = "sortDir", defaultValue = AppConstants.SORT_DIR, required = false) String sortDir){
        PostResponse postResponse = this.postService.getPostByUser(userId, pageNumber, pageSize, sortBy, sortDir);

        return new ResponseEntity<>(postResponse, HttpStatus.OK);
    }

    //search post by title
    @GetMapping("/posts/search/{searchKeyword}")
    public ResponseEntity<List<PostDto>> searchPosts(@PathVariable("searchKeyword") String searchKeyword){
        List<PostDto> posts = this.postService.searchPosts(searchKeyword);

        return new ResponseEntity<>(posts, HttpStatus.OK);
    }

    //upload file
    @Operation(security = { @SecurityRequirement(name = "bearer-key") })
    @PostMapping("/post/image/upload/{postId}")
    public ResponseEntity<PostDto> uploadFile(@RequestParam(value = "file") MultipartFile file,
                                              @PathVariable("postId") Integer postId) throws IOException {
        PostDto postDto = this.postService.getPostById(postId);

        try {
            String fileName = this.fileService.uploadFile(path, file);
            postDto.setImageName(fileName);
            PostDto updatedPostDto = this.postService.updatePost(postDto, postId);

            return new ResponseEntity<>(updatedPostDto, HttpStatus.OK);

        }catch (Exception e){
            e.getMessage().concat("Please select a file");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }



    }

    //download file
    @GetMapping(value = "/post/image/{imageName}", produces = MediaType.ALL_VALUE)
    public void downloadFile(@PathVariable("imageName") String imageName,
                                          HttpServletResponse response) throws IOException {

        InputStream resource = this.fileService.getResource(path, imageName);
        response.setContentType(MediaType.ALL_VALUE);
        StreamUtils.copy(resource, response.getOutputStream());
    }

}
