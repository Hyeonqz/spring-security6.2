package org.spring.securityexample1;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class A {

	@Bean // @Bean 꼭 등록 해야함,,
	public SecurityFilterChain filterChain (HttpSecurity http) throws Exception {
		http
			.formLogin((auth) -> auth
				// 우리가 Custom 한 로그인 페이지 경로를 적는다, 자동으로 redirection 을 해준다.
				.loginPage("/login")
				// html 로그인 id,password 를 특정한 경로로 보낸다 -> Post 방식임.
				.loginProcessingUrl("/loginProc").permitAll()
			);

		return http.build();
	}

}
