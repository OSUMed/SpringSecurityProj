package com.srikanth.security.demo.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.HashMap;
import com.srikanth.security.demo.domain.User;
import com.srikanth.security.demo.repository.UserRepository;
import com.srikanth.security.demo.response.AuthenticationResponse;
import com.srikanth.security.demo.service.JwtService;
import com.srikanth.security.demo.service.UserService;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private JwtService jwtService;
    private UserService userService;
    
    public UserController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        super();
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // For Non-JWT version:
//    @PostMapping("")
//    public ResponseEntity<User> signUpUser (@RequestBody User user) {
//        user.setPassword(passwordEncoder.encode(user.getPassword()));
//        User savedUser = userRepository.save(user);
//        
//        return ResponseEntity.ok(savedUser);
//    }
    @PostMapping("")
    public ResponseEntity<AuthenticationResponse> signUpUser (@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        User savedUser = userRepository.save(user);
        
        String token = jwtService.generateToken(new HashMap<>(), savedUser);
        
        return ResponseEntity.ok(new AuthenticationResponse(savedUser.getUsername(), token));
    }
    
    
    
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> signInUser(@RequestBody User user) {
        UserDetails loggedInUser = userService.loadUserByUsername(user.getUsername());
        String token = jwtService.generateToken(new HashMap<>(), loggedInUser);
        
        return ResponseEntity.ok(new AuthenticationResponse(loggedInUser.getUsername(), token));
    }
}