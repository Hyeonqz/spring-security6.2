package org.spring.securityjwt.config;

import java.util.Collections;

import org.spring.securityjwt.jwt.CustomLogoutFilter;
import org.spring.securityjwt.jwt.refresh.RefreshRepository;
import org.spring.securityjwt.jwt.JwtFilter;
import org.spring.securityjwt.jwt.JwtUtils;
import org.spring.securityjwt.jwt.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final AuthenticationConfiguration configuration;
	private final RefreshRepository refreshRepository;
	private final JwtUtils jwtUtils;

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// AuthenticationManager Bean 등록 -> 이걸 해야 new LogginFilter 안에 주입할 수 있다.
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		// csrf disable
		http.csrf(AbstractHttpConfigurer::disable); // (auth) -> auth.disable() 위 로직을 메소드 참조 시킴

		// cors 설정
		http
			.cors((cors) -> cors
				.configurationSource(new CorsConfigurationSource() {
					@Override
					public CorsConfiguration getCorsConfiguration (HttpServletRequest request) {
						CorsConfiguration corsConfiguration = new CorsConfiguration();
						corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
						corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
						corsConfiguration.setAllowCredentials(true);
						corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));
						corsConfiguration.setMaxAge(3600L);

						return corsConfiguration;
					}
				})
			);

		http
			.formLogin((auth) -> auth.disable());

		http
			.httpBasic((auth) -> auth.disable());

		// 경로별 인가 작업
		http.authorizeHttpRequests((auth) -> auth
			.requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
			.requestMatchers("/api/**").permitAll()
			.requestMatchers("/admin/**","/admin").hasRole("ADMIN")
			.anyRequest().authenticated()
		);

		// JWT 필터 등록
		http
			.addFilterBefore(new JwtFilter(jwtUtils), LoginFilter.class) // 로그인 필터 전에 다른 필터를 등록하겠다는 뜻 -> 뒤 클래스는 스프링 시큐리티 기본 객체임
		;

		// 로그인 검증 필터 추가
		http
			// (어떤 필터 등록할지 , 등록할 위치를 어디로 할것인가)
			.addFilterAt(
				new LoginFilter(authenticationManager(configuration), jwtUtils, refreshRepository),
				UsernamePasswordAuthenticationFilter.class)
		;

		// 로그아웃 필터
		http
			.addFilterBefore(new CustomLogoutFilter(jwtUtils, refreshRepository), LogoutFilter.class) // 로그아웃 필터 전에 다 등록을 하겠다는 뜻
			;

		// 세션 설정 -> JWT 는 Stateless 상태로 관리하는 것이 제일 중요하다.
		http.sessionManagement((session) -> session
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		);

		return http.build();
	}
}

