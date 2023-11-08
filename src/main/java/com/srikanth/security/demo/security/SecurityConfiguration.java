package com.srikanth.security.demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

import com.srikanth.security.demo.service.UserService;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	// User Details Service: Load user by user name:
    @Bean
    public UserDetailsService userDetailsService () {
        return new UserService();
    }
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((request) -> {
        	
        	// All users get access
        	request.requestMatchers("/free").permitAll();
        	
        	// Any role who is authenticated get access:
        	request.requestMatchers("/authonly").authenticated();
        	
        	// Only people who logged in and has access "USER", 
        	// Other endpoints not in previous rules -> get all access 
        	request.requestMatchers("/products").hasAnyRole("USER")
            .anyRequest().permitAll();
        })
        //if you want simple form Java Security, render the template
//        .formLogin((form)->{form.loginPage("/login").permitAll()});
        
        // Adds regular log in:
        .userDetailsService(userDetailsService())
        .formLogin(Customizer.withDefaults());
        
        
//        authorizeHttpRequests().requestMatchers("/public/**").permitAll().anyRequest()
//                .hasRole("USER").and()
//                // Possibly more configuration ...
//                .formLogin() // enable form based log in
//                // set permitAll for all URLs associated with Form Login
//                .permitAll();
        return http.build();
    }

}