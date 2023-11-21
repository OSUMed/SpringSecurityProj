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

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;
import com.srikanth.security.demo.service.JwtService;
import com.srikanth.security.demo.service.UserService;
import com.srikanth.security.demo.util.CookieUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;

import org.springframework.stereotype.Component;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

@Component
// Once per request filter: because it passes by just once
// Where we get the tokens via req.headers
public class JwtAuthenticationFilter extends OncePerRequestFilter implements ApplicationContextAware {

	private JwtService jwtService;
	private ApplicationContext applicationContext;
	private RefreshTokenService refreshTokenService;

	// Requests:
	// Headers -> key/value pairs (Authorization -> Bearer xxx.yyy.zzz)
	// Body -> (if JSON) key/value pairs
//    String auth = request.getHeader("Authorization");

	public JwtAuthenticationFilter(JwtService jwtService, RefreshTokenService refreshTokenService) {
		super();
		this.jwtService = jwtService;
		this.refreshTokenService = refreshTokenService;
	}

	// Copy paste this code@
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// Requests:
		// Headers -> key/value pairs (Authorization -> Bearer xxx.yyy.zzz)
		// Body -> (if JSON) key/value pairs
		// For REST Controller
//        String authHeader = request.getHeader("Authorization");
//        if (StringUtils.hasText(authHeader)) {
//        	String token = authHeader.substring(7);
		
		
		// Get Cookies:
		Cookie accessTokenCookie = findCookie(request, "accessToken");
		Cookie refreshTokenCookie = findCookie(request, "refreshToken");
		
		if (accessTokenCookie != null) {

			// If subject and authentication valid -> check token validity. If valid -> set in security context:
			String token = accessTokenCookie.getValue();
			try {
				String subject = jwtService.getSubject(token);
				Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

				if (StringUtils.hasText(subject) && authentication == null) {
					if (jwtService.isTokenValid(token, getUserDetails(subject))) {
						setAuthenticationInContext(subject);
					}
				}
				
			// If token is expired, refresh access token and set in security context:
	        } catch (ExpiredJwtException e) {
	            // Access Token is expired, try to refresh it:
	            try {
	                System.out.println("Access Token Expired!");
	                String newToken = refreshAccessToken(refreshTokenCookie);
	                accessTokenCookie = CookieUtils.createAccessTokenCookie(newToken);
	                response.addCookie(accessTokenCookie);
	                setAuthenticationInContext(jwtService.getSubject(newToken));
	            } catch (ExpiredJwtException e1) {
	                // Refresh Token is also expired
	                System.out.println("Refresh Token Expired!");
	                e1.printStackTrace();
	                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	                response.sendRedirect("/logout"); // Redirect to the "Bad Token" view
	                return; // Important to return and not continue the filter chain
	            } catch (Exception e1) {
	                // Handle other exceptions during token refresh
	            	System.out.println("e1 Refreshh Token Expired!");
	                e1.printStackTrace();
	                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	                response.sendRedirect("/logout"); // Redirect to the "Bad Token" view
	                return; // Important to return and not continue the filter chain
	            }
	        } catch (Exception e) {
	            // Handle general 401 Unauthorized here
	            e.printStackTrace();
	            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	            response.sendRedirect("/bad-token"); // Redirect to the "Bad Token" view
	            return; // Important to return and not continue the filter chain
	        }
		}
		filterChain.doFilter(request, response);
	}
	

	private UserDetails getUserDetails(String username) {
		UserDetailsService userDetailsService = applicationContext.getBean(UserDetailsService.class);
		return userDetailsService.loadUserByUsername(username);
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		// TODO Auto-generated method stub
		this.applicationContext = applicationContext;

	}

	private String refreshAccessToken(Cookie refreshTokenCookie) throws Exception {
		String newAccessToken = refreshTokenService
				.createNewAccessToken(new RefreshTokenRequest(refreshTokenCookie.getValue()));
		return newAccessToken;
	}

	private void setAuthenticationInContext(String username) {
		// Create final UsernamePasswordAuthenticationToken token. Then set it into security context
		// Notice we add user's roles here so spring security can check against it later
		UserDetails userDetails = getUserDetails(username);
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null,
				userDetails.getAuthorities());
		
		// Create and then set the authToken into the security context:
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(authToken);
		SecurityContextHolder.setContext(securityContext);
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