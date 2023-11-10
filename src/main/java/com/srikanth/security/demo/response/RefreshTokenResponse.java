package com.srikanth.security.demo.response;

public record RefreshTokenResponse(
        String username,
        String token) {

}