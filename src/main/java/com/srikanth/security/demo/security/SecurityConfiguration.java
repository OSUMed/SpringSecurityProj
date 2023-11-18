package com.srikanth.security.demo.security;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import java.io.IOException;
import java.util.HashMap;

import org.springframework.security.core.Authentication;

import com.srikanth.security.demo.domain.RefreshToken;
import com.srikanth.security.demo.domain.User;
import com.srikanth.security.demo.repository.UserRepository;
import com.srikanth.security.demo.service.JwtService;
import com.srikanth.security.demo.service.RefreshTokenService;
import com.srikanth.security.demo.service.UserService;
import com.srikanth.security.demo.util.CookieUtils;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
	private UserRepository userRepository;
	private JwtAuthenticationFilter jwtAuthenticationFilter;
	private JwtService jwtService;
	private RefreshTokenService refreshTokenService;

	public SecurityConfiguration(UserRepository userRepository, JwtAuthenticationFilter jwtAuthenticationFilter,
			JwtService jwtService, RefreshTokenService refreshTokenService) {
		super();
		this.userRepository = userRepository;
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
		this.jwtService = jwtService;
		this.refreshTokenService = refreshTokenService;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		// On default use
		return new BCryptPasswordEncoder();
	}

	// User Details Service: Load user by user name:
	@Bean
	public UserDetailsService userDetailsService() {
		return new UserService(userRepository);
	}

	@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
          .authorizeHttpRequests((request) -> {
            request
                   .requestMatchers("/api/v1/users", "/api/v1/users/**").permitAll()
                   .requestMatchers("/free").permitAll()
                   .anyRequest().authenticated();
        })
        .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authenticationProvider(authenticationProvider())
          .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .formLogin(this::configureFormLogin);


	return http.build();

	}

	private void configureFormLogin(FormLoginConfigurer<HttpSecurity> login) {
		System.out.println("We are loggin in...");
		login.loginPage("/viewlogin").failureUrl("/login-error").successHandler(this::onAuthenticationSuccess)
				.failureHandler(this::onAuthenticationFailure) // Set the custom failure handler
				.permitAll();
	}

	// Auth successful? -> Create the access/refresh tokens and add to response:
	private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {
		// Get the authenticated user's details (principal)
		User user = (User) authentication.getPrincipal();

		// Log user details
		System.out.println("Authentication successful for user: " + user.getUsername());
		System.out.println("User Authorities/Roles: " + user.getAuthorities());
		String accessToken = jwtService.generateToken(new HashMap<>(), user);
		RefreshToken refreshToken = refreshTokenService.generateRefreshToken(user);

		Cookie accessTokenCookie = CookieUtils.createAccessTokenCookie(accessToken);
		Cookie refreshTokenCookie = CookieUtils.createRefeshTokenCookie(refreshToken.getRefreshToken());
		response.addCookie(refreshTokenCookie);
		response.addCookie(accessTokenCookie);

		response.sendRedirect("/products");
	}

	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		// Get the username and password from the login request
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		String role = request.getParameter("roleName");

		// Log authentication failure details
		System.out.println("Authentication failed for user: " + username);
		System.out.println("Authentication failed for user rolen: " + role);
		System.out.println("Authentication failure exception: " + exception.getMessage());

		// Log the provided credentials and expected credentials
		System.out.println("Provided Username: " + username);
		System.out.println("Provided Password: " + password);
		System.out.println("Expected Username: <Your expected username>");
		System.out.println("Expected Password: <Your expected password>");

		// You can perform additional actions here if needed, such as redirecting to an
		// error page
		// For now, let's redirect to the login error page
		response.sendRedirect("/login-error");
	}

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.csrf(AbstractHttpConfigurer::disable).authorizeHttpRequests((request) -> {
//        	
//        	// All users get access
//        	request.requestMatchers("/").permitAll();
//        	request.requestMatchers("/login").permitAll();
//        	request.requestMatchers("/free").permitAll();
//        	
//        	// Any role who is authenticated get access:
//        	request.requestMatchers("/authonly").authenticated();
//        	
//        	// Only people who logged in and has access "USER", 
//        	// Other endpoints not in previous rules -> get all access 
//        	request.requestMatchers("/products").authenticated();
//        })
//        //if you want simple form Java Security, render the template
////        .formLogin((form)->{form.loginPage("/login").permitAll()});
//        
//        // Adds regular log in:
//        .authenticationProvider(authenticationProvider())
//        // Add this filter for the Jwt authentication
//        // 1st param: our jwt filter ; 2nd param: the jwt grader found in spring security
//        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
////        .formLogin(Customizer.withDefaults());		// Won't work if you have Req.Headers Authorization strategy
//        
//        
////        authorizeHttpRequests().requestMatchers("/public/**").permitAll().anyRequest()
////                .hasRole("USER").and()
////                // Possibly more configuration ...
////                .formLogin() // enable form based log in
////                // set permitAll for all URLs associated with Form Login
////                .permitAll();
//        return http.build();
//    }

	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
		daoAuthenticationProvider.setUserDetailsService(userDetailsService());
		return daoAuthenticationProvider;
	}

}