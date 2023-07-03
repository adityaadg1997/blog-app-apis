package com.codewithaditya.blog.services.impl;

import com.codewithaditya.blog.config.AppConstants;
import com.codewithaditya.blog.entitiles.Role;
import com.codewithaditya.blog.entitiles.User;
import com.codewithaditya.blog.exceptions.ResourceNotFoundException;
import com.codewithaditya.blog.payloads.UserDto;
import com.codewithaditya.blog.repositories.RoleRepo;
import com.codewithaditya.blog.repositories.UserRepo;
import com.codewithaditya.blog.services.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private ModelMapper modelMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RoleRepo roleRepo;

    @Override
    public UserDto registerNewUser(UserDto userDto) {

        User user = this.modelMapper.map(userDto, User.class);

        //encode password then save into DB
        String encodedPassword = this.passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);

        //roles
        Role role = this.roleRepo.findById(AppConstants.NORMAL_USER).get();
        user.getRoles().add(role);

        User newUser = this.userRepo.save(user);

        return this.modelMapper.map(newUser, UserDto.class);
    }

    @Override
    public UserDto createUser(UserDto userDto) {

        User user = this.dtoToUser(userDto);
        User savedUser = this.userRepo.save(user);

        return this.userToDto(savedUser);
    }

    @Override
    public UserDto getUserById(Integer userId) {

        User userById = this.userRepo.findById(userId).orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        return this.userToDto(userById);
    }

    @Override
    public List<UserDto> getAllUsers() {

        List<User> usersList = this.userRepo.findAll();
        List<UserDto> userDtos = usersList.stream().map(user -> this.userToDto(user)).collect(Collectors.toList());

        return userDtos;
    }

    @Override
    public UserDto updateUser(UserDto userDto, Integer userId) {

        User user = this.userRepo.findById(userId).orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        user.setName(userDto.getName());
        user.setEmail(userDto.getEmail());
        user.setPassword(userDto.getPassword());
        user.setAbout(userDto.getAbout());

        User updatedUser = this.userRepo.save(user);

        return this.userToDto(updatedUser);
    }

    @Override
    public void deleteUser(Integer userId) {
        User user = this.userRepo.findById(userId).orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        this.userRepo.delete(user);

    }

    public User dtoToUser(UserDto userDto){
        User user = this.modelMapper.map(userDto, User.class);

//        user.setId(userDto.getId());
//        user.setName(userDto.getName());
//        user.setEmail(userDto.getEmail());
//        user.setPassword(userDto.getPassword());
//        user.setAbout(userDto.getAbout());

        return user;
    }

    public UserDto userToDto(User user){
        UserDto userDto = this.modelMapper.map(user, UserDto.class);

//        userDto.setId(user.getId());
//        userDto.setName(user.getName());
//        userDto.setEmail(user.getEmail());
//        userDto.setPassword(user.getPassword());
//        userDto.setAbout(user.getAbout());

        return userDto;
    }
}
