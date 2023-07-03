package com.codewithaditya.blog.services;

import com.codewithaditya.blog.payloads.UserDto;

import java.util.List;

public interface UserService {

    //register new user
    UserDto registerNewUser(UserDto userDto);

    UserDto createUser(UserDto user);

    UserDto getUserById(Integer userId);

    List<UserDto> getAllUsers();

    UserDto updateUser(UserDto userDto, Integer userId);

    void deleteUser(Integer userId);
}
