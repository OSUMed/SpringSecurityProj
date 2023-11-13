package com.srikanth.security.demo.security;

import java.io.IOException;

import org.springframework.web.filter.OncePerRequestFilter;

import com.srikanth.security.demo.request.RefreshTokenRequest;
import com.srikanth.security.demo.service.JwtService;
import com.srikanth.security.demo.service.RefreshTokenService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;
import com.srikanth.security.demo.service.JwtService;
import com.srikanth.security.demo.service.UserService;
import com.srikanth.security.demo.util.CookieUtils;

import io.jsonwebtoken.ExpiredJwtException;

import org.springframework.stereotype.Component;

@Component
// Once per request filter: because it passes by just once
// Where we get the tokens via req.headers
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private JwtService jwtService;
	private UserService userService;
	private RefreshTokenService refreshTokenService;

	// Requests:
	// Headers -> key/value pairs (Authorization -> Bearer xxx.yyy.zzz)
	// Body -> (if JSON) key/value pairs
//    String auth = request.getHeader("Authorization");

	public JwtAuthenticationFilter(JwtService jwtService, UserService userService,
			RefreshTokenService refreshTokenService) {
		super();
		this.jwtService = jwtService;
		this.userService = userService;
		this.refreshTokenService = refreshTokenService;
	}

	// Copy paste this code@
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// Requests:
		// Headers -> key/value pairs (Authorization -> Bearer xxx.yyy.zzz)
		// Body -> (if JSON) key/value pairs
		
		// Get the Cookies:
		Cookie accessTokenCookie = null;
		Cookie refreshTokenCookie = null;

		if (request.getCookies() != null) {
			for (Cookie cookie : request.getCookies()) {
				if (cookie.getName().equals("accessToken")) {
					accessTokenCookie = cookie;
				} else if (cookie.getName().equals("refreshToken")) {
					refreshTokenCookie = cookie;
				}
			}
		}

		// For REST Controller
//        String authHeader = request.getHeader("Authorization");
//        if (StringUtils.hasText(authHeader)) {
		if (accessTokenCookie != null) {
			// hey, we have a token (probably) in the request
			// let's see if this token is a valid JWS or not
//        	String token = authHeader.substring(7);
			int loginTryCount = 0;
			while (loginTryCount <= 2) {
				String token = accessTokenCookie.getValue();

				try {
					String subject = jwtService.getSubject(token);
					Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

					if (StringUtils.hasText(subject) && authentication == null) {
						UserDetails userDetails = userService.loadUserByUsername(subject);

						if (jwtService.isTokenValid(token, userDetails)) {
							SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
							UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
									userDetails, userDetails.getPassword(), userDetails.getAuthorities());
							securityContext.setAuthentication(authToken);
							SecurityContextHolder.setContext(securityContext);
							break;
						}
					}
				} catch (ExpiredJwtException e) {
					// TODO Auto-generated catch block
					try {
						token = refreshTokenService.createNewAccessToken(new RefreshTokenRequest(refreshTokenCookie.getValue()));
						accessTokenCookie = CookieUtils.createAccessTokenCookie(token);
						response.addCookie(accessTokenCookie);
					} catch (Exception e1) {
						// Problem creating a new access token. Ignore it, inc logintryCount, and goes to next filter(login again)
						e1.printStackTrace();
					}
				}
				loginTryCount++;
			}
		}
		filterChain.doFilter(request, response);
	}

}