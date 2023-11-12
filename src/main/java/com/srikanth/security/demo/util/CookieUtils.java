package com.srikanth.security.demo.util;

import java.util.HashMap;

import com.srikanth.security.demo.domain.RefreshToken;

import jakarta.servlet.http.Cookie;

public class CookieUtils {
	public static Cookie createAccessTokenCookie(String value) {
		Cookie accessTokenCookie = new Cookie("accessToken", value);
		return accessTokenCookie;
	}

	public static Cookie createRefeshTokenCookie(String value) {
		
		Cookie accessRefreshCookie = new Cookie("refreshToken", value);
		return accessRefreshCookie;
	}

}
