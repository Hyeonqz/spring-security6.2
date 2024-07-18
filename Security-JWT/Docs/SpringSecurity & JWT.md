# SpringSecurity & JWT 로그인 사용방법

## 코드만 설명

#### 기본 Security 설정
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		// csrf disable
		http.csrf(AbstractHttpConfigurer::disable); // (auth) -> auth.disable() 위 로직을 메소드 참조 시킴

		// FormLogin 방식 disable
		http.formLogin(AbstractHttpConfigurer::disable);

		// Http Basic 인증 방식 disable
		http.httpBasic(AbstractHttpConfigurer::disable);

		// 경로별 인가 작업
		http.authorizeHttpRequests((auth) -> auth
			.requestMatchers("/api/**", "/").permitAll()
			.requestMatchers("/admin/**").hasRole("ADMIN")
			.anyRequest().authenticated()
		);

		// 세션 설정 -> JWT 는 Stateless 상태로 관리하는 것이 제일 중요하다.
		http.sessionManagement((session) -> session
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		);

		return http.build();
	}
}

```