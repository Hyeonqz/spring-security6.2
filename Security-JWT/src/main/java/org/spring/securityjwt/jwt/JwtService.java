package org.spring.securityjwt.jwt;

import java.util.Date;

import org.spring.securityjwt.jwt.refresh.RefreshEntity;
import org.spring.securityjwt.jwt.refresh.RefreshRepository;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class JwtService {
	private final JwtUtils jwtUtils;
	private final RefreshRepository refreshRepository;

	public void issueRefreshToken(HttpServletRequest request, HttpServletResponse response) {
		// get refresh_token
		String refresh_token = null;
		Cookie[] cookies = request.getCookies();
		for(Cookie cookie : cookies) {
			if(cookie.getName().equals("Refresh_Token")) {
				refresh_token = cookie.getValue();
			}
		}

		if(refresh_token == null) {
			throw new RuntimeException("Refresh Token is Null");
		}

		// expire check
		try {
			jwtUtils.isTokenExpired(refresh_token);
		} catch (ExpiredJwtException e) {
			throw new RuntimeException("Refresh Token is Expired");
		}

		// 토큰이 refresh 인지 체크
		String category = jwtUtils.getCategory(refresh_token);

		if(!category.equals("Refresh_Token")) {
			throw new RuntimeException("This is not refresh Token");
		}

		// DB 에 저장되어 있는지 확인
		Boolean isExist = refreshRepository.existsByRefresh(refresh_token);

		if(!isExist) {
			throw new RuntimeException("Invalid Refresh Token is exist");
		}


		String username = jwtUtils.getUsername(refresh_token);
		String role = jwtUtils.getRole(refresh_token);
		String newAccessToken = jwtUtils.createToken("Access_Token",username,role,600000L);
		String newRefreshToken = jwtUtils.createToken("Refresh_Token",username,role,86400000L);

		refreshRepository.deleteByRefresh(refresh_token); // 기존 refreshToken 삭제
		addRefreshTokenEntity(username, newRefreshToken, 86400000L);

		//response.addHeader("Authorization", "Bearer " + newAccessToken);
		response.addCookie(jwtUtils.createCookie("Refresh_Token", newRefreshToken));
		response.setHeader("Access_Token",newAccessToken);
	}

	private void addRefreshTokenEntity(String username, String refresh, Long expiredMs) {
		Date date = new Date(System.currentTimeMillis() + expiredMs);

		RefreshEntity refreshEntity = new RefreshEntity();
		refreshEntity.setUsername(username);
		refreshEntity.setRefresh(refresh);
		refreshEntity.setExpiredAt(date);

		refreshRepository.save(refreshEntity);
	}
}
