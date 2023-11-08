package com.srikanth.security.demo.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.srikanth.security.demo.domain.User;

// implement spring security's user details service interface:
public class UserService implements UserDetailsService {

	// Returns UserDetails instead of User bc that is how their API returns:
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
        User user = new User(username, "abc123");
        
        return user;
    }

}