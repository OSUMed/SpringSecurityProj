package com.srikanth.security.demo.response;

public record AuthenticationResponse(
        String username,
        String accessToken,
        String refreshToken) {

}