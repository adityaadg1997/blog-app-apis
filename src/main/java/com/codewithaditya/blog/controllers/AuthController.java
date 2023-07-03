package com.codewithaditya.blog.controllers;

import com.codewithaditya.blog.exceptions.ApiException;
import com.codewithaditya.blog.payloads.JWTAuthRequest;
import com.codewithaditya.blog.payloads.JWTAuthResponse;
import com.codewithaditya.blog.payloads.UserDto;
import com.codewithaditya.blog.security.JWTTokenHelper;
import com.codewithaditya.blog.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @Autowired
    private JWTTokenHelper jwtTokenHelper;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    //login
    @PostMapping("/login")
    public ResponseEntity<JWTAuthResponse> createToken(
            @RequestBody JWTAuthRequest request
            ) throws Exception {

        this.authenticate(request.getUsername(), request.getPassword());

        UserDetails userDetails = this.userDetailsService.loadUserByUsername(request.getUsername());

        String token = this.jwtTokenHelper.generateToken(userDetails);

        JWTAuthResponse response = new JWTAuthResponse();
        response.setToken(token);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    private void authenticate(String username, String password) throws Exception {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        try {
            this.authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        }catch (BadCredentialsException e){
                System.out.println("Invalid Details");
             throw new ApiException("Username or Password is Invalid !!");
        }

    }

    //register new user
    @PostMapping("/register")
    public ResponseEntity<UserDto> registerNewUser(@RequestBody UserDto userDto){
        UserDto registerUser = this.userService.registerNewUser(userDto);

        return new ResponseEntity<>(registerUser, HttpStatus.CREATED);


    }
}
