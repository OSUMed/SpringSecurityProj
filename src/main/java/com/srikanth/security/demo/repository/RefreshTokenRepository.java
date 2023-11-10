package com.srikanth.security.demo.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.srikanth.security.demo.domain.RefreshToken;
import com.srikanth.security.demo.domain.User;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {
    
	// Returns that one user name that matches with String 'username'
    User findByUsername(String username);
    
    Optional<RefreshToken> findByRefreshToken(String refreshToken);
}