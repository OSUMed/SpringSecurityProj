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
	public String getsignUpUser() {
		return "signup";
	}

	@GetMapping("/login")
	public String loginUser() {
		return "login";
	}

	@PostMapping("/signup")
	public String signUpUser(User user) {
		System.out.println("user is: " + user);
		User savedUser = userService.registerNewUser(user.getUsername(), user.getPassword());
		return "redirect:/login";
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

	@GetMapping("/red/welcome")
	public String welcomeRedUsers(Model model) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String currentUserName = null;

		if (authentication != null) {
			currentUserName = authentication.getName(); // This gets the username
		}
		model.addAttribute("teamName", "Red");
		model.addAttribute("username", currentUserName);
		return "red-user";
	}

	@GetMapping("/blue/welcome")
	public String welcomeBlueUsers(Model model) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String currentUserName = null;

		if (authentication != null) {
			currentUserName = authentication.getName(); // This gets the username
		}
		model.addAttribute("teamName", "Blue");
		model.addAttribute("username", currentUserName);
		return "blue-user";
	}

	@GetMapping("/green/welcome")
	public String welcomeGreenUsers(Model model) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String currentUserName = null;

		if (authentication != null) {
			currentUserName = authentication.getName(); // This gets the username
		}
		model.addAttribute("teamName", "Green");
		model.addAttribute("username", currentUserName);
		return "green-user";
	}

	@GetMapping("/red/1")
	public String welcomeRed1(Model model) {
		model.addAttribute("message", "This is red-1");
		model.addAttribute("teamName", "Red");
		return "red-1"; // HTML page name should be red-1.html
	}
	
	@GetMapping("/green/1")
	public String welcomeGreen1(Model model) {
		model.addAttribute("message", "This is green-1");
		model.addAttribute("teamName", "Green");
		return "green-1"; // HTML page name should be green-1.html
	}
	
	@GetMapping("/blue/1")
	public String welcomeBlue1(Model model) {
		model.addAttribute("message", "This is blue-1");
		model.addAttribute("teamName", "Blue");
		return "blue-1"; // HTML page name should be blue-1.html
	}
	@GetMapping("/red/2")
	public String welcomeRed2(Model model) {
		model.addAttribute("message", "This is red-2");
		model.addAttribute("teamName", "Red");
		return "red-1"; // HTML page name should be red-1.html
	}

	@GetMapping("/green/2")
	public String welcomeGreen2(Model model) {
		model.addAttribute("message", "This is green-2");
		model.addAttribute("teamName", "Green");
		return "green-1"; // HTML page name should be green-1.html
	}

	@GetMapping("/blue/2")
	public String welcomeBlue2(Model model) {
		model.addAttribute("message", "This is blue-2");
		model.addAttribute("teamName", "Blue");
		return "blue-1"; // HTML page name should be blue-1.html
	}

}
