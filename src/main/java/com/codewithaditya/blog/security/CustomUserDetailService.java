package com.codewithaditya.blog.security;

import com.codewithaditya.blog.entitiles.User;
import com.codewithaditya.blog.exceptions.ResourceNotFoundException;
import com.codewithaditya.blog.repositories.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailService implements UserDetailsService {

    @Autowired
    private UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //loading user from database by username
        User user = this.userRepo.findByEmail(username).orElseThrow(() -> new ResourceNotFoundException("username", "email : " + username, 404));

        return user;
    }
}