package com.srikanth.security.demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

// Example URL -> http://localhost:8080/products
    
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