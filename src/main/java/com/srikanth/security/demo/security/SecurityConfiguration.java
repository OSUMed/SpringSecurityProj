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
import java.util.Collection;
import java.util.HashMap;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;

import com.srikanth.security.demo.domain.RefreshToken;
import com.srikanth.security.demo.domain.User;
import com.srikanth.security.demo.repository.AuthorityRepository;
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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
	@Autowired
	private JwtAuthenticationFilter jwtAuthenticationFilter;
	@Autowired
	private JwtService jwtService;
	@Autowired
	private RefreshTokenService refreshTokenService;
	@Autowired
	private UserService userService;

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

//	@Bean
//	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//		String pathsPermitAll = "\"/api/v1/users\", \"/allusers\", \"/api/v1/users/**\", \"/h2-console/**\", \"/free\", \"/signup\"";
//		http.csrf(AbstractHttpConfigurer::disable).authorizeHttpRequests(authz -> {
//			authz.requestMatchers(new AntPathRequestMatcher(pathsPermitAll)).permitAll()
//					.requestMatchers(new AntPathRequestMatcher("/user/welcome")).authenticated() // Public endpoint
//					.requestMatchers(new AntPathRequestMatcher("/admin/**")).hasAuthority("ROLE_ADMIN") 
//					.requestMatchers(new AntPathRequestMatcher("/user/**")).hasAuthority("ROLE_USER") 
//					.requestMatchers(new AntPathRequestMatcher("/blue/**")).hasAuthority("ROLE_BLUE") 
//					.requestMatchers(new AntPathRequestMatcher("/red/**")).hasAuthority("ROLE_RED") 
//					.requestMatchers(new AntPathRequestMatcher("/green/**")).hasAuthority("ROLE_GREEN"); 
//			authz.anyRequest().authenticated(); 
//		}).headers(headers -> headers
//				// Disable frame options for H2 Console
//				.frameOptions(frameOptions -> frameOptions.disable()))
////				.sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//				.authenticationProvider(authenticationProvider())
//				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//				.formLogin(this::configureFormLogin)
//				.logout(logoutConfigurer -> {
//			            logoutConfigurer
//			                .logoutUrl("/perform_logout") // URL to trigger the logout
//			                .logoutSuccessUrl("/login") // URL to redirect after logout
//			                .deleteCookies("accessToken") // Cookies to delete upon logout
//			                .deleteCookies("refreshToken") // Cookies to delete upon logout
//			                .invalidateHttpSession(true) // Invalidate session
//			                .clearAuthentication(true); // Clear authentication
//			        });
//
//		return http.build();
//
//	}
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	    String[] pathsPermitAll = { "/api/v1/users", "/allusers", "/api/v1/users/**", "/h2-console/**", "/free", "/signup" };
	    http.csrf(AbstractHttpConfigurer::disable)
	        .authorizeHttpRequests(authz -> {
	            for (String path : pathsPermitAll) {
	                authz.requestMatchers(new AntPathRequestMatcher(path)).permitAll();
	            }
	            authz.requestMatchers(new AntPathRequestMatcher("/user/welcome")).authenticated()
	                 .requestMatchers(new AntPathRequestMatcher("/admin/**")).hasAuthority("ROLE_ADMIN")
	                 .requestMatchers(new AntPathRequestMatcher("/user/**")).hasAuthority("ROLE_USER")
	                 .requestMatchers(new AntPathRequestMatcher("/blue/**")).hasAuthority("ROLE_BLUE")
	                 .requestMatchers(new AntPathRequestMatcher("/red/**")).hasAuthority("ROLE_RED")
	                 .requestMatchers(new AntPathRequestMatcher("/green/**")).hasAuthority("ROLE_GREEN")
	                 .anyRequest().authenticated();
	        })
	        .headers(frameOptions -> frameOptions.disable())
	        .authenticationProvider(authenticationProvider())
	        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
	        .formLogin(this::configureFormLogin)
	        .logout(logoutConfigurer -> {
	            logoutConfigurer.logoutUrl("/perform_logout")
	                .logoutSuccessUrl("/login")
	                .deleteCookies("accessToken", "refreshToken")
	                .invalidateHttpSession(true)
	                .clearAuthentication(true);
	        });

	    return http.build();
	}

	private void configureFormLogin(FormLoginConfigurer<HttpSecurity> login) {
		login.loginPage("/login") // Listens to POST /viewlogin and sends it to spring sec( user details service
									// -> loadUserByUsername )
				.successHandler(this::onAuthenticationSuccess) // Set the custom success handler
				.failureHandler(this::onAuthenticationFailure) // Set the custom failure handler
//	         .defaultSuccessUrl("/products", false) // Set the default page after login
				.permitAll();
	}

	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		User user = (User) authentication.getPrincipal(); // Cast to your User domain object
		System.out.println("Authentication successful for user: " + user.getUsername());
		System.out.println("Authorities: " + user.getAuthorities());
		// Log user details
		System.out.println("Authentication successful for user: " + user.getUsername());

		// Create and add cookies
		String accessToken = jwtService.generateToken(new HashMap<>(), user);
		RefreshToken refreshToken = refreshTokenService.generateRefreshToken(user);
		Cookie accessTokenCookie = CookieUtils.createAccessTokenCookie(accessToken);
		Cookie refreshTokenCookie = CookieUtils.createRefeshTokenCookie(refreshToken.getRefreshToken());
		response.addCookie(accessTokenCookie);
		response.addCookie(refreshTokenCookie);

		// Determine the redirect URL based on the user's authorities
		String redirectUrl = determineRedirectUrl(user.getAuthorities());
		System.out.println("Redirecting to: " + redirectUrl);

		// Perform the redirect
		response.sendRedirect(redirectUrl);
	}

	private String determineRedirectUrl(Collection<? extends GrantedAuthority> authorities) {
		if (authorities.stream().anyMatch(a -> "ROLE_RED".equals(a.getAuthority()))) {
			return "/red/welcome";
		} else if (authorities.stream().anyMatch(a -> "ROLE_BLUE".equals(a.getAuthority()))) {
			return "/blue/welcome";
		} else if (authorities.stream().anyMatch(a -> "ROLE_GREEN".equals(a.getAuthority()))) {
			return "/green/welcome";
		} else {
			return "/user/welcome"; // Default redirect URL
		}
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