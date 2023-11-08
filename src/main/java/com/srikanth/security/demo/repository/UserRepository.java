package com.srikanth.security.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.srikanth.security.demo.domain.User;

public interface UserRepository extends JpaRepository<User, Integer> {
    
	// Returns that one user name that matches with String 'username'
    User findByUsername(String username);
}