package com.srikanth.security.demo.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.srikanth.security.demo.domain.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {
    
    Optional<RefreshToken> findByUser_Username(String username);
    
    Optional<RefreshToken> findByRefreshToken(String refreshToken);
}
