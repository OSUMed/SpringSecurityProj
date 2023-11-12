package com.srikanth.security.demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.srikanth.security.demo.repository.UserRepository;
import com.srikanth.security.demo.service.UserService;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    private UserRepository userRepository;
    private JwtAuthenticationFilter jwtAuthenticationFilter;
    
    public SecurityConfiguration(UserRepository userRepository, JwtAuthenticationFilter jwtAuthenticationFilter) {
		super();
		this.userRepository = userRepository;
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
	}

	@Bean
    public PasswordEncoder passwordEncoder () {
	 // On default use
        return new BCryptPasswordEncoder();
    }

	// User Details Service: Load user by user name:
    @Bean
    public UserDetailsService userDetailsService () {
        return new UserService(userRepository);
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
          .authorizeHttpRequests((request) -> {
            request
                   .requestMatchers("/api/v1/users").permitAll()
                   .requestMatchers("/api/v1/users/**").permitAll()
                   .requestMatchers("/free").permitAll()
                   .anyRequest().authenticated();
        })
        .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authenticationProvider(authenticationProvider())
          .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
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
    public AuthenticationProvider authenticationProvider () {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        return daoAuthenticationProvider;
    }

}