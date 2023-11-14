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

import jakarta.servlet.http.HttpServletRequest;

// implement spring security's user details service interface:
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

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
	    User user = userRepository.findByUsername(username);
	    if (user == null) {
	        throw new UsernameNotFoundException("User not found with username: " + username);
	    }
	    
	    // Get the roleName from the request
	    HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
	    String roleName = request.getParameter("roleName");

	    // Use the roleName to set the user's authorities
	    Authority authority_ui = authorityRepository.findByName(roleName);
	    user.setAuthorities(Collections.singletonList(authority_ui));

	    // Create UserDetails from the loaded user
	    UserDetails userDetails = new org.springframework.security.core.userdetails.User(
	            user.getUsername(),
	            user.getPassword(),
	            user.getAuthorities().stream()
	                    .map(authority -> new SimpleGrantedAuthority(authority.getAuthority()))
	                    .collect(Collectors.toList())
	    );

	    // Print the UserDetails object and authorities
	    System.out.println("Loaded UserDetails: " + userDetails);
	    System.out.println("Authorities/Roles: " + userDetails.getAuthorities());

	    String encodedPassword = userDetails.getPassword();
	    System.out.println("Encoded Password: " + encodedPassword);

	    return userDetails;
	}


	public Optional<User> findById(Integer userId) {
		return userRepository.findById(userId);
	}

	public User registerNewUser(String username, String password) {
	    User user = new User(username, passwordEncoder.encode(password));
//	    Authority authority = authorityRepository.findByName(roleName);
//	    user.setAuthorities(Collections.singletonList(authority));
	    return userRepository.save(user);
	}


}