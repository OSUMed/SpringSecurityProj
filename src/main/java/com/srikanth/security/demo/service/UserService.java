package com.srikanth.security.demo.service;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Primary;
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
@Primary
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
	
	public List<User> getAllUsers() {
		return userRepository.findAll();
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	    User user = userRepository.findByUsername(username);
	    if (user == null) {
	        System.out.println("User not found with username: " + username);
	        throw new UsernameNotFoundException("User not found");
	    }
	    System.out.println("User found: " + username + ", Authorities: " + user.getAuthorities());
	    return user;
	}


    public Optional<User> findById (Integer userId) {
        return userRepository.findById(userId);
    }
    
    public User registerNewUser(String username, String password) {
        User user = new User(username, passwordEncoder.encode(password));

        // List of possible roles
        List<String> roles = Arrays.asList("ROLE_BLUE", "ROLE_RED", "ROLE_GREEN");
        // Randomly select a role
        String randomRole = roles.get(new Random().nextInt(roles.size()));

        // Find the authority by name
        Authority authority = authorityRepository.findByName(randomRole);

        // Set the selected authority
        user.setAuthorities(Collections.singletonList(authority));

        
        return userRepository.save(user);
    }
    



}