package com.srikanth.security.demo.service;

import java.util.Collections;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.srikanth.security.demo.domain.Authority;
import com.srikanth.security.demo.domain.User;
import com.srikanth.security.demo.repository.AuthorityRepository;
import com.srikanth.security.demo.repository.UserRepository;

// implement spring security's user details service interface:
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {


	private UserRepository userRepository;
	private AuthorityRepository authorityRepository;
	private PasswordEncoder passwordEncoder;

    
	public UserService(UserRepository userRepository, AuthorityRepository authorityRepository,
			PasswordEncoder passwordEncoder) {
		super();
		this.userRepository = userRepository;
		this.authorityRepository = authorityRepository;
		this.passwordEncoder = passwordEncoder;
	}

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
//        User user = new User(username, passwordEncoder.encode("abc123"));
    	User user = userRepository.findByUsername(username);
        
        if (user == null) throw new UsernameNotFoundException("Bad Credentials");
        
        return user;
    }

    public Optional<User> findById (Integer userId) {
        return userRepository.findById(userId);
    }
    
    public User registerNewUser(String username, String password, String roleName) {
	    User user = new User(username, passwordEncoder.encode(password));
	    Authority authority = authorityRepository.findByName(roleName);
	    user.setAuthorities(Collections.singletonList(authority));
	    return userRepository.save(user);
	}

}