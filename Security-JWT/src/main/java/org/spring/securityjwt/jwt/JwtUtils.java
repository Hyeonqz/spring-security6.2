package org.spring.securityjwt.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtUtils {
	private SecretKey secretKey;

	public JwtUtils (@Value("${spring.jwt.secret.key}") String secretKey) {
		this.secretKey = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
	}

	// jwt 검증
	public String getUsername(String token) {
		return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
	}

	public String getRole(String token) {
		return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
	}

	public String getCategory(String token) {
		return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
	}

	public Boolean isTokenExpired(String token) {
		return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
	}

	// header 에 refresh token 을 cookie 에 저장
	public Cookie createCookie (String key, String value) {
		Cookie cookie = new Cookie(key,value);
		cookie.setMaxAge(24*60*60);
		// cookie.setSecure(true); // https 설정 할 경우 넣어줘야
		// cookie.setPath("/"); cookie 경로 설정
		cookie.setHttpOnly(true);
		return cookie;
	}

	// jwt 생성(refresh + access 둘다 생성 가능)
	public String createToken(String category, String username, String role, Long expiredAt) {
		long now = System.currentTimeMillis();
		long expirationTime = now + expiredAt * 2000;
		//log.info("Current Time: {}", new Date(now));
		//log.info("Expiration Time: {}", new Date(expirationTime));

		return Jwts.builder()
			.claim("category", category) // access 인지, refresh 인지 체크
			.claim("username", username)
			.claim("role", role)
			.issuedAt(new Date(now))
			.expiration(new Date(expirationTime))
			.signWith(secretKey)
			.compact();
	}
}
