package com.srikanth.security.demo.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.srikanth.security.demo.domain.RefreshToken;
import com.srikanth.security.demo.domain.User;
import com.srikanth.security.demo.repository.RefreshTokenRepository;
import com.srikanth.security.demo.repository.UserRepository;
import com.srikanth.security.demo.response.AuthenticationResponse;
import com.srikanth.security.demo.service.JwtService;
import com.srikanth.security.demo.service.RefreshTokenService;
import com.srikanth.security.demo.service.UserService;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

@Controller
public class LoginLogoutController {
	private UserRepository userRepository;
	private PasswordEncoder passwordEncoder;
	private JwtService jwtService;
	private UserService userService;
	private RefreshTokenRepository refreshTokenRepository;
	private RefreshTokenService refreshTokenService;

	public LoginLogoutController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService,
			UserService userService, RefreshTokenService refreshTokenService) {
		super();
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.userService = userService;
		this.refreshTokenService = refreshTokenService;
	}
	
    @GetMapping("/signup")
    public String getsignUpUser () {
    	return "signup";
	}
    @PostMapping("/signup")
    public String signUpUser (@RequestBody User user) {
//        user.setPassword(passwordEncoder.encode(user.getPassword()));
//        User savedUser = userRepository.save(user);
    	userService.registerNewUser(user.getUsername(), user.getPassword());
    	return "redirect:/login";
    }

	@GetMapping("login")
	public String viewLogin() {
		return "login";
	}
	@GetMapping("login-error")
	public String loginError(Model model) {
		model.addAttribute("loginError", true);
		return "login";
	}
	@GetMapping("user/welcome")
	public String welcomeUsers(Model model) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String currentUserName = null;
		
		if (authentication != null) {
			currentUserName = authentication.getName(); // This gets the username
		}
		
		model.addAttribute("username", currentUserName);
		return "user";
	}
	@GetMapping("red/welcome")
	public String welcomeRedUsers(Model model) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String currentUserName = null;
		
		if (authentication != null) {
			currentUserName = authentication.getName(); // This gets the username
		}
		
		model.addAttribute("username", currentUserName);
		return "red-user";
	}
	@GetMapping("blue/welcome")
	public String welcomeBlueUsers(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUserName = null;

        if (authentication != null) {
            currentUserName = authentication.getName(); // This gets the username
        }

        model.addAttribute("username", currentUserName);
		return "blue-user";
	}

}
