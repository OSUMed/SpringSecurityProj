package com.srikanth.security.demo.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.Authentication;

@Controller
public class LoginLogoutController {

	@GetMapping("viewlogin")
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
