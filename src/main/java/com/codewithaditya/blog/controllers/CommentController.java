package com.codewithaditya.blog.controllers;

import com.codewithaditya.blog.payloads.ApiResponse;
import com.codewithaditya.blog.payloads.CommentDto;
import com.codewithaditya.blog.services.CommentService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/comments")
public class CommentController {

    @Autowired
    private CommentService commentService;


    @Operation(security = { @SecurityRequirement(name = "bearer-key") })
    @PostMapping("/user/{userId}/post/{postId}/comment")
    public ResponseEntity<CommentDto> createComment(@PathVariable("userId") Integer userId,
                                                    @PathVariable("postId") Integer postId,
                                                    @RequestBody CommentDto commentDto){
        CommentDto comment = this.commentService.createComment(userId, postId, commentDto);

        return new ResponseEntity<>(comment, HttpStatus.CREATED);
    }

    @Operation(security = { @SecurityRequirement(name = "bearer-key") })
    @DeleteMapping("/comment/{commentId}")
    public ResponseEntity<ApiResponse> createComment(@PathVariable("commentId") Integer commentId){
        this.commentService.deleteComment(commentId);

        return new ResponseEntity<>(new ApiResponse("Comments with CommentId " + commentId + " successfully deleted !!", true), HttpStatus.OK);
    }
}
