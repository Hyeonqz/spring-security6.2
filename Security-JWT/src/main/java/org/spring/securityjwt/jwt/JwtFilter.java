package org.spring.securityjwt.jwt;

import java.io.IOException;
import java.io.PrintWriter;

import org.spring.securityjwt.application.service.CustomUserDetails;
import org.spring.securityjwt.domain.Role;
import org.spring.securityjwt.domain.UserEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
public class JwtFilter extends OncePerRequestFilter {
	private final JwtUtils jwtUtils;

	/** 요청에 대해서 한번만 동작한다*/
	@Override
	protected void doFilterInternal (HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {

		// 헤더에서 access키에 담긴 토큰을 꺼냄
		String accessToken = request.getHeader("Access_Token");

		// 토큰이 없다면 다음 필터로 넘김
		if (accessToken == null) {
			filterChain.doFilter(request, response); // 다음 필터로 넘긴다.
			return ;
		}

		// 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
		try {
			jwtUtils.isTokenExpired(accessToken);
		} catch (ExpiredJwtException e) {

			//response body
			PrintWriter writer = response.getWriter();
			writer.print("Access token expired");

			//response status code
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return ;
		}

		// 토큰이 Access_Token 인지 확인 (발급시 페이로드에 명시)
		String category = jwtUtils.getCategory(accessToken);

		if (!category.equals("Access_Token")) {

			//response body
			PrintWriter writer = response.getWriter();
			writer.print("invalid Access_Token");

			//response status code
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		// username, role 값을 획득
		String username = jwtUtils.getUsername(accessToken);
		String role = jwtUtils.getRole(accessToken);

		UserEntity userEntity = new UserEntity();
		userEntity.setUsername(username);
		userEntity.setRole(Role.USER);
		userEntity.setPassword("password");

		CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

		Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(authToken);

		filterChain.doFilter(request, response);

	}

}
