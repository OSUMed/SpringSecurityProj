package com.srikanth.security.demo.service;


import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.srikanth.security.demo.domain.User;
import com.srikanth.security.demo.repository.UserRepository;

// implement spring security's user details service interface:
import org.springframework.stereotype.Component;

@Component
public class UserService implements UserDetailsService {


    private UserRepository userRepository;
    
    public UserService(UserRepository userRepository) {
        super();
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
//        User user = new User(username, passwordEncoder.encode("abc123"));
    	User user = userRepository.findByUsername(username);
        
        if (user == null) throw new UsernameNotFoundException("Bad Credentials");
        
        return user;
    }

}