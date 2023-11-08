package com.srikanth.security.demo.service;


import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.srikanth.security.demo.domain.User;

// implement spring security's user details service interface:

public class UserService implements UserDetailsService {

    private PasswordEncoder passwordEncoder;
    
    public UserService(PasswordEncoder passwordEncoder) {
        super();
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
        User user = new User(username, passwordEncoder.encode("abc123"));
        
        return user;
    }

}