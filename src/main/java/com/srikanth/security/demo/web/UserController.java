package com.srikanth.security.demo.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.HashMap;
import java.util.List;

import com.srikanth.security.demo.domain.RefreshToken;
import com.srikanth.security.demo.domain.User;
import com.srikanth.security.demo.repository.RefreshTokenRepository;
import com.srikanth.security.demo.repository.UserRepository;
import com.srikanth.security.demo.request.RefreshTokenRequest;
import com.srikanth.security.demo.response.AuthenticationResponse;
import com.srikanth.security.demo.response.RefreshTokenResponse;
import com.srikanth.security.demo.service.JwtService;
import com.srikanth.security.demo.service.RefreshTokenService;
import com.srikanth.security.demo.service.UserService;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {
	private UserRepository userRepository;
	private PasswordEncoder passwordEncoder;
	private JwtService jwtService;
	private UserService userService;
	private RefreshTokenRepository refreshTokenRepository;
	private RefreshTokenService refreshTokenService;

	public UserController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService,
			UserService userService, RefreshTokenService refreshTokenService) {
		super();
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.userService = userService;
		this.refreshTokenService = refreshTokenService;
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
//        user.setPassword(passwordEncoder.encode(user.getPassword()));
//        User savedUser = userRepository.save(user);
    	User savedUser = userService.registerNewUser(user.getUsername(), user.getPassword());
        
        String accessToken = jwtService.generateToken(new HashMap<>(), savedUser);
        RefreshToken refreshToken = refreshTokenService.generateRefreshToken(savedUser);

		return ResponseEntity
				.ok(new AuthenticationResponse(savedUser.getUsername(), accessToken, refreshToken.getRefreshToken()));
	}

	@PostMapping("/login")
	public ResponseEntity<AuthenticationResponse> loginUser(@RequestBody User user) {
		User loggedInUser = (User) userService.loadUserByUsername(user.getUsername());
		String accessToken = jwtService.generateToken(new HashMap<>(), loggedInUser);
		RefreshToken refreshToken = refreshTokenService.generateRefreshToken(loggedInUser);

		return ResponseEntity.ok(
				new AuthenticationResponse(loggedInUser.getUsername(), accessToken, refreshToken.getRefreshToken()));
	}

	@PostMapping("/refreshtoken")
	public ResponseEntity<RefreshTokenResponse> getNewAccessToken(
			@RequestBody RefreshTokenRequest refreshTokenRequest) {
		String accessToken = refreshTokenService.createNewAccessToken(refreshTokenRequest);
		return ResponseEntity.ok(new RefreshTokenResponse(accessToken, refreshTokenRequest.refreshToken()));
	}
	
	@GetMapping("/getusers")
	public List<User> getUsers() {
		return userService.getAllUsers();
	}
}