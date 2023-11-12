package com.srikanth.security.demo.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

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

}
