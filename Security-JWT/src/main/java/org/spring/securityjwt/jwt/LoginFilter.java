package org.spring.securityjwt.jwt;

import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.spring.securityjwt.application.service.CustomUserDetails;
import org.spring.securityjwt.jwt.refresh.RefreshEntity;
import org.spring.securityjwt.jwt.refresh.RefreshRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
	private final AuthenticationManager authenticationManager;
	private final JwtUtils jwtUtils;
	private final RefreshRepository refreshRepository;

	// INFO: 혹시라도 나중에 username 이 아닌 -> 필드 이름을 다른 것으로 바꾸고 싶다면 이 부분부터 수정해야함..
	@Override
	protected String obtainUsername(HttpServletRequest request) {
		String username = request.getParameter("username");
		log.info("Username from request: {}", username);
		return (username != null) ? username.trim() : "";
	}

	@Override
	protected String obtainPassword(HttpServletRequest request) {
		String password = request.getParameter("password");
		log.info("Password from request: {}", password);
		return (password != null) ? password : "";
	}

	// 여기서 만든 filter 들은 SecurityConfig 에 등록을 해줘야 한다.
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

		//클라이언트 요청에서 username, password 추출
		String username = this.obtainUsername(request);
		String password = this.obtainPassword(request);

		//스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

		//token에 담은 검증을 위한 AuthenticationManager로 전달
		return authenticationManager.authenticate(authToken);
	}

	//로그인 성공시 실행 메소드
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

		CustomUserDetails userDetails = (CustomUserDetails)authentication.getPrincipal();
		String username =  userDetails.getUsername();

		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
		Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
		GrantedAuthority auth = iterator.next();
		String role = auth.getAuthority();

		// 토큰 생성
		String accessToken = jwtUtils.createToken("Access_Token",username,role,600000L); // 10분
		String refreshToken = jwtUtils.createToken("Refresh_Token",username,role,86400000L); //24시간

		// refresh Token 저장
		addRefreshTokenEntity(username,refreshToken, 86400000L);

		// HTTP 인증 방식은 RFC7235 정의에 따라 아래 인증 헤더 형태를 가져야 한다.
		response.addHeader("Authorization", "Bearer " + accessToken);
		response.setHeader("Access_Token", accessToken);
		response.addCookie(jwtUtils.createCookie("Refresh_Token",refreshToken));
		response.setStatus(HttpStatus.OK.value());

		log.info("[Authorization Access_Token] : [{}]", accessToken);
		log.info("[Authorization Refresh_Token] : [{}]", refreshToken);

		log.info("Success Login");
	}

	//로그인 실패시 실행하는 메소드
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
		response.setStatus(401);
		log.info("Unsuccessful Login");
	}

	// Refresh_Token DB 에 저장
	private void addRefreshTokenEntity(String username, String refresh, Long expiredMs) {
		Date date = new Date(System.currentTimeMillis() + expiredMs);

		RefreshEntity refreshEntity = new RefreshEntity();
		refreshEntity.setUsername(username);
		refreshEntity.setRefresh(refresh);
		refreshEntity.setExpiredAt(date);

		refreshRepository.save(refreshEntity);
	}
}
