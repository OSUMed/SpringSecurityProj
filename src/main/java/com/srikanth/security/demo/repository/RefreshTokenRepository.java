package com.srikanth.security.demo.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.srikanth.security.demo.domain.RefreshToken;
import com.srikanth.security.demo.domain.User;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {
    
    Optional<RefreshToken> findByUser_Username(String username);
    
    // For refreshing access token
    Optional<RefreshToken> findByRefreshToken(String refreshToken);
    
    // For login
    Optional<RefreshToken> findByUser(User user);

}
