package org.spring.securityexample1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;

@Configuration // 이 클래스는 스프링 부트 한테 Config 클래스로 등록이 된다.
@EnableWebSecurity // 스프링 시큐리티 한테도 관리를 받게 하기 위함.
public class SecurityConfig {

	/*
	* 인가 설정
	* */
	@Bean // @Bean 꼭 등록 해야함,,
	public SecurityFilterChain filterChain (HttpSecurity http) throws Exception {

		http
			// 특정 경로에 요청을 허용하거나 거부하거나 할 수 있게 한다.
			.authorizeHttpRequests((auth) -> auth
				// "/" 및 "/login" 은 모든 사람 접근 가능하게 함
				.requestMatchers("/", "/login","/loginProc","/join", "/joinProc").permitAll()
				// Hierarchy 설정 -> 접근 권한 A, B, C 설정
				.requestMatchers("/").hasAnyRole("A","B","C")
				.requestMatchers("/manage").hasAnyRole("B","C")
				.requestMatchers("/master").hasRole("C")
				// "/admin" 관리자 페이지는 Role 이 ADMIN 인 사람만 접근 가능하게 함. -> ROLE_ADMIN
				.requestMatchers("/admin").hasRole("ADMIN")
				// "/**" 는 {id} 같은거 의미, hasAnyRole 은 여러 역할 처리함, 그리고 hasAnyRole 을 하면 접미사에 'ROLE_' 을 붙여준다.
				.requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
				// anyRequest 는 등록되지 않은 나머지 경로를 다 처리한다.
				.anyRequest().authenticated()
			);

		http
			.formLogin((auth) -> auth
				.loginPage("/login") // 우리가 Custom 한 로그인 페이지 경로를 적는다, 자동으로 redirection 을 해준다.
				.loginProcessingUrl("/loginProc") // html 로그인 id,password 를 특정한 경로로 보낸다 -> Post 방식임.
				.permitAll()
			);

		http
			.logout((auth) -> auth
				.logoutUrl("/logout")
				.logoutSuccessUrl("/")
			);
		// CSRF 설정, Post 요청시 csrf 토큰도 보내줘야 로그인이 됨.
		http
			.csrf(AbstractHttpConfigurer::disable
			);

		// 세션 관리 설정
		http
			.sessionManagement((auth) -> auth
				.maximumSessions(2) // 하나의 아이디에 대한 다중 로그인 허용 개수, 로그인이 되있는 상태에서 2개 기기에 더 로그인할 수 있다.
				.maxSessionsPreventsLogin(true) // true: 초과시 새로운 로그인 차단, false : 초과시 기존 세션 하나 삭제
			);

		// 세션 보호 설정
		http
			.sessionManagement((auth) -> auth
				.sessionFixation().changeSessionId() // 로그인 시 동일한 세션에 대한 id 변경
			);

		// http basic 방식 로그인
		http
			.httpBasic(Customizer.withDefaults()
			);

		return http.build();
		// }

	}

	// Hierarchy 설정
	@Bean
	public RoleHierarchy roleHierarchy() {
		return RoleHierarchyImpl.fromHierarchy(
			"ROLE_C > ROLE_B > \n" + "ROLE_B > ROLE_A");
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// 인메모리 방식 User 저장 -> 유저 각각의 넣어줘야 한다.
	// DB 를 연결하지 않아도, 서버 실행시 자동으로 메모리에 올라가 있는다.
	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user1 = User.builder()
			.username("user1")
			.password(passwordEncoder().encode("1234"))
			.roles("ADMIN")
			.build();

		UserDetails user2 = User.builder()
			.username("user2")
			.password(passwordEncoder().encode("1234"))
			.roles("ADMIN")
			.build();

		return new InMemoryUserDetailsManager(user1,user2);
	}


}