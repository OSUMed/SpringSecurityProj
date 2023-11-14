package com.srikanth.security.demo.security;

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
import com.srikanth.security.demo.repository.AuthorityRepository;
import com.srikanth.security.demo.repository.UserRepository;
import com.srikanth.security.demo.service.JwtService;
import com.srikanth.security.demo.service.RefreshTokenService;
import com.srikanth.security.demo.service.UserService;
import com.srikanth.security.demo.util.CookieUtils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
	private UserRepository userRepository;
	private JwtAuthenticationFilter jwtAuthenticationFilter;
	private JwtService jwtService;
	private RefreshTokenService refreshTokenService;
	private AuthorityRepository authorityRepository;
	private PasswordEncoder passwordEncoder;
	@Autowired
    private UserService userService;

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
		return userService;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	    http
	        .csrf(AbstractHttpConfigurer::disable)
	        .authorizeHttpRequests(authz -> {
	            authz
	                .requestMatchers("/api/v1/users", "/api/v1/users/**", "/free").permitAll() // Public endpoints
	                .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN") // Admin-only endpoints
	                .requestMatchers("/user/**").hasAuthority("ROLE_USER"); // User-only endpoints
	            authz
	                .anyRequest().authenticated(); // All other requests must be authenticated
	        })
	        .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
	        .authenticationProvider(authenticationProvider())
	        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
	        .formLogin(this::configureFormLogin);

	    return http.build();
	}


//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//    	 String[] publicEndpoints = new String[] {
//    		        "/api/v1/users",
//    		        "/api/v1/users/**",
//    		        "/free"
//    	 };
//        http.csrf(AbstractHttpConfigurer::disable)
//          .authorizeHttpRequests((request) -> {
//            request
//                   .requestMatchers(publicEndpoints).permitAll()
//                   .anyRequest().authenticated();
//        })
//        .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//        .authenticationProvider(authenticationProvider())
//        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//        .formLogin(this::configureFormLogin);
//
//        return http.build();
//    }
//    
	private void configureFormLogin(FormLoginConfigurer<HttpSecurity> login) {
		login.loginPage("/viewlogin").failureUrl("/login-error").successHandler(this::onAuthenticationSuccess)
				.permitAll();
	}

	// Auth successful? -> Create the access/refresh tokens and add to response:
	private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {
		System.out.println("authentication is: " + authentication);
		User user = (User) authentication.getPrincipal();
		String accessToken = jwtService.generateToken(new HashMap<>(), user);
		RefreshToken refreshToken = refreshTokenService.generateRefreshToken(user);

		Cookie accessTokenCookie = CookieUtils.createAccessTokenCookie(accessToken);
		Cookie refreshTokenCookie = CookieUtils.createRefeshTokenCookie(refreshToken.getRefreshToken());
		response.addCookie(refreshTokenCookie);
		response.addCookie(accessTokenCookie);

		response.sendRedirect("/products");
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

	// The key player in comparing the request's cookie with the H2 db deets:
	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
		daoAuthenticationProvider.setUserDetailsService(userDetailsService());
		return daoAuthenticationProvider;
	}

}