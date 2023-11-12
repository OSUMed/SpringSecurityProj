package com.srikanth.security.demo.service;

import java.util.Date;
import java.util.HashMap;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.srikanth.security.demo.domain.RefreshToken;
import com.srikanth.security.demo.domain.User;
import com.srikanth.security.demo.repository.RefreshTokenRepository;
import com.srikanth.security.demo.request.RefreshTokenRequest;

@Service
public class RefreshTokenService {

	@Value("${jwt.refreshTokenExpirationTimeInMillis}")
	private Long refreshTokenExpirationTimeInMillis;

	private UserService userService;
	private RefreshTokenRepository refreshTokenRepository;
	private JwtService jwtService;

	public RefreshTokenService(UserService userService, RefreshTokenRepository refreshTokenRepository, JwtService jwtService) {
		super();
		this.userService = userService;
		this.refreshTokenRepository = refreshTokenRepository;
		this.jwtService = jwtService;
	}

	// To ensure id is not null, if user in repo, then make refresh token.
	// Save the new refresh token to our repo and then return the refresh token from
	// our repo. That is the workflow!
	public RefreshToken generateRefreshToken(Integer userId) {

		Optional<User> userOpt = userService.findById(userId);
		if (userOpt.isPresent()) {
			Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findById(userId);

			RefreshToken refreshToken = null;
			if (refreshTokenOpt.isPresent()) {
				refreshToken = refreshTokenOpt.get();
				refreshToken.setExpirationDate(getRefreshTokenExpirationDate());
				refreshToken.setRefreshToken(generateRandomTokenValue());
			} else {
				refreshToken = new RefreshToken(userOpt.get(), generateRandomTokenValue(),
						getRefreshTokenExpirationDate());
			}

			refreshToken = refreshTokenRepository.save(refreshToken);
			return refreshToken;
		}
		return null;
	}

	private String generateRandomTokenValue() {
		return UUID.randomUUID().toString();
	}

	private Date getRefreshTokenExpirationDate() {
		return new Date(System.currentTimeMillis() + refreshTokenExpirationTimeInMillis);
	}

    public String createNewAccessToken(RefreshTokenRequest refreshTokenRequest) {
        Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findByRefreshToken(refreshTokenRequest.refreshToken());
        // TODO: write code to check that the RefreshToken hasn't expired
        String accessToken = refreshTokenOpt.map(RefreshTokenService::isNonExpired)
                .map(refreshToken -> jwtService.generateToken(new HashMap<>(), refreshToken.getUser()))
                .orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));
        
        return accessToken;
        
    }
    
    private static RefreshToken isNonExpired (RefreshToken refreshToken) {
        if (refreshToken.getExpirationDate().after(new Date())) {
            return refreshToken;
        } else {
            throw new IllegalArgumentException("Refresh Token has expired");
        }
    }
    
    
}