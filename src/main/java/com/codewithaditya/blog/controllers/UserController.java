package com.codewithaditya.blog.controllers;

import com.codewithaditya.blog.payloads.ApiResponse;
import com.codewithaditya.blog.payloads.UserDto;
import com.codewithaditya.blog.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    //CREATE

    @Operation(security = { @SecurityRequirement(name = "bearer-key") })
    @PostMapping("/")
    public ResponseEntity<UserDto> createUser(@Valid @RequestBody UserDto userDto) {
        UserDto user = this.userService.createUser(userDto);

        return new ResponseEntity(user, HttpStatus.CREATED);
    }

    //GET
    @GetMapping("/")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        return new ResponseEntity<>(this.userService.getAllUsers(), HttpStatus.OK);
    }

    //GET user by id
    @GetMapping("/{userId}")
    public ResponseEntity<UserDto> getUser(@PathVariable("userId") Integer userId) {
        return new ResponseEntity<>(this.userService.getUserById(userId), HttpStatus.OK);
    }

    //PUT
    @Operation(security = { @SecurityRequirement(name = "bearer-key") })
    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUser(@Valid @RequestBody UserDto userDto, @PathVariable("userId") Integer userId) {

        return new ResponseEntity<>(this.userService.updateUser(userDto, userId), HttpStatus.ACCEPTED);
    }

    //ADMIN ONLY
    //DELETE
    @Operation(security = { @SecurityRequirement(name = "bearer-key") })
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{userId}")
    public ResponseEntity<ApiResponse> deleteUser(@PathVariable("userId") Integer userId) {
        this.userService.deleteUser(userId);
        return new ResponseEntity<>(new ApiResponse("user with userId " + userId + " is successfully deleted", true), HttpStatus.OK);
    }
}
