package com.srikanth.security.demo.security;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.srikanth.security.demo.request.RefreshTokenRequest;
import com.srikanth.security.demo.service.JwtService;
import com.srikanth.security.demo.service.RefreshTokenService;
import com.srikanth.security.demo.service.UserService;
import com.srikanth.security.demo.util.CookieUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private JwtService jwtService;
    private RefreshTokenService refreshTokenService;

    public JwtAuthenticationFilter(JwtService jwtService, @Lazy RefreshTokenService refreshTokenService) {
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Cookie accessTokenCookie = findCookie(request, "accessToken");
        Cookie refreshTokenCookie = findCookie(request, "refreshToken");

        if (accessTokenCookie != null) {
            String token = accessTokenCookie.getValue();
            try {
                if (jwtService.isTokenValid(token, null)) { // UserDetails parameter is not used for basic JWT validation
                    setSecurityContext(token);
                }
            } catch (ExpiredJwtException e) {
                try {
					token = refreshTokenService.createNewAccessToken(new RefreshTokenRequest(refreshTokenCookie.getValue()));
                    accessTokenCookie = CookieUtils.createAccessTokenCookie(token);
                    response.addCookie(accessTokenCookie);
                    setSecurityContext(token); // Set security context with new token
                } catch (Exception ex) {
                    ex.printStackTrace(); // Log the exception
                }
            }
        }
        filterChain.doFilter(request, response);
    }

    private void setSecurityContext(String token) {
        Claims claims = jwtService.extractAllClaims(token);
        String username = claims.getSubject();
        List<SimpleGrantedAuthority> authorities = ((List<?>) claims.get("authorities")).stream()
            .map(auth -> new SimpleGrantedAuthority((String) auth))
            .collect(Collectors.toList());

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private Cookie findCookie(HttpServletRequest request, String name) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals(name)) {
                    return cookie;
                }
            }
        }
        return null;
    }
}
