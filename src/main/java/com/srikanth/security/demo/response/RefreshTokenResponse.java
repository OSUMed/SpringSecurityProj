package com.srikanth.security.demo.response;

public record RefreshTokenResponse(
        String accessToken,
        String refreshToken) {

}