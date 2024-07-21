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

### Entity & Repository
```java
public interface UserRepository extends JpaRepository<UserEntity, Long> {
}

@Builder
@AllArgsConstructor @NoArgsConstructor
@Getter @Setter @ToString
@Entity
public class UserEntity {

	@Id @GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String LoginId;
	private String password;

	@Column(columnDefinition = "varchar(20)")
	@Enumerated(EnumType.STRING)
	private Role role;
}
```

편의를 위해 Getter,Setter 및 생성자,빌더 롬복을 사용했습니다 <br>

## 회원가입
<hr>

### Repository
```java
public interface UserRepository extends JpaRepository<UserEntity, Long> {
	Boolean existsByLoginId(String loginId);
}
```

### Entity
```java
@EntityListeners(AuditingEntityListener.class)
@Builder
@AllArgsConstructor @NoArgsConstructor
@Getter @Setter @ToString
@Entity(name="user")
public class UserEntity {

	@Id @GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String loginId;
	private String password;

	@Column(columnDefinition = "varchar(20)")
	@Enumerated(EnumType.STRING)
	private Role role;

	@CreatedDate
	private LocalDateTime createAt;

	@LastModifiedDate
	private LocalDateTime updateAt;

}
```

### DTO
```java
@Builder
@Getter @Setter
public class RegisterDTO {

	private String loginId;
	private String password;
	private Role role;
	private LocalDateTime createdAt;
}
```

### Service
```java
@Transactional(readOnly = true)
@RequiredArgsConstructor
@Service
public class RegisterService {
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder passwordEncoder;

	@Transactional
	public RegisterDTO register(RegisterDTO registerDTO) {
		String loginId = registerDTO.getLoginId();
		String password = registerDTO.getPassword();

		Boolean isExist = userRepository.existsByLoginId(loginId);

		if(isExist) {
			throw new RuntimeException("동일한 ID가 존재합니다");
		}

		UserEntity user = new UserEntity();
		user.setLoginId(loginId);
		user.setPassword(passwordEncoder.encode(password));
		user.setRole(Role.USER);
		user.setCreateAt(LocalDateTime.now());
		user.setUpdateAt(LocalDateTime.now());

		userRepository.save(user);

		return RegisterDTO.builder()
			.loginId(user.getLoginId())
			.password(user.getPassword())
			.role(user.getRole())
			.createdAt(user.getCreateAt())
			.build();

	}
}

```

### Controller
```java
@RequiredArgsConstructor
@RequestMapping("/api")
@RestController
public class RegisterController {
	private final RegisterService registerService;

	@PostMapping("/register")
	public ResponseEntity<RegisterDTO> joinProcess(@RequestBody RegisterDTO registerDTO) {
		RegisterDTO register = registerService.register(registerDTO);
		return ResponseEntity.ok(register);
	}
}
```

## 로그인
<hr>

SpringSecurity 를 추가하면 서블릿 컨테이너에서 DelegatingFilter 가 등록이 되어 모든 요청을 가로 챈다 <br>
그 후 Config 해둔 SecurityFilterChain 부분으로 요청을 넘겨 내부 처리 후 다시 DelegatingFilter 로 넘겨준다 <br>

- 아이디, 비밀번호 검증을 위한 커스텀 필터 작성
- DB에 저장되어 있는 회원 정보를 기반으로 검증할 로직 작성
- 로그인 성공시 JWT 를 반환할 Success 핸들러 생성
- 커스텀 필터 SecurityConfig 등록

### 로그인 필터 구현 filter ~ DB기반 로그인 검증 로직 
```java
public interface UserRepository extends JpaRepository<UserEntity, Long> {
	Boolean existsByUsername(String username);
	UserEntity findByUsername(String username);
}
```
```java
@Slf4j
@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		log.info("loadUserByUsername {}", username);
		UserEntity user = userRepository.findByUsername(username);

		if (user == null) {
			log.error("User not found with username: {}", username);
			throw new UsernameNotFoundException("User not found with username: " + username);
		}

		log.info("User found: {}", user);
		return new CustomUserDetails(user);
	}

}
```
```java
public class CustomUserDetails implements UserDetails {
	private final UserEntity userEntity;

	public CustomUserDetails (UserEntity userEntity) {
		this.userEntity = userEntity;
	}

	/** 데이터를 검증해서 넘겨주는 DTO 역할을 한다. */

	// Role 값 반환
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities () {
		Collection<GrantedAuthority> collection = new ArrayList<>();

		collection.add(new GrantedAuthority() {
			@Override
			public String getAuthority () {
				return userEntity.getRole().getDescription();
			}
		});

		return collection;
	}

	// 비밀번호 값 반환
	@Override
	public String getPassword () {
		return userEntity.getPassword();
	}

	// 아이디 값 반환
	@Override
	public String getUsername () {
		return userEntity.getUsername();
	}

	// 계정이 만료가 되었는지
	@Override
	public boolean isAccountNonExpired () {
		return true;
	}

	// 계정이 락 되어쓴ㄴ지
	@Override
	public boolean isAccountNonLocked () {
		return true;
	}

	// 계정신용이 유효한지
	@Override
	public boolean isCredentialsNonExpired () {
		return true;
	}

	@Override
	public boolean isEnabled () {
		return true;
	}

}
```
```java
@Slf4j
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
	private final AuthenticationManager authenticationManager;

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

	//로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
		log.info("Success Login");
	}

	//로그인 실패시 실행하는 메소드
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
		log.info("Unsuccessful Login");
	}

}
```

로컬에서 이제 /login api 를 post 로 호출을 하면 로그인이 성공한 것을 볼 수 있습니다 <br>
/login api 는 만들지 않았는데 호출이 되는 이유는
```java
	private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/login",
			"POST");
```

위 상수가 선언되어 있기 때문에 가능하다 <br>

> 로그인 성공 -> JWT 발급
> > 사용자 접근시 JWT 검증

JWT 원리 -> Json 타입을 웹 토큰임 <br>
1) Header -> jwt 명시, 사용된 암호화 알고리즘 명시, 즉 간단한 토큰 정보
2) Payload -> 사용자가 집어넣어둔 사용자 정보
3) Signature -> 암호화 알고리즘( header + payload + 암호화키)

payload 는 외부에서 디코딩을 통하여 정보를 알 수 있다 <br>
그러므로 외부에서 알아도 되는 정보만 담아야 한다 <br>

대칭키 : HS256 <br>
비대칭키 : SHA256 <br>


```java
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

	public Boolean isTokenExpired(String token) {
		return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
	}

	// jwt 생성
	public String createToken(String username, String role, Long expiredAt) {
		return Jwts.builder()
			.claim("username",username)
			.claim("role",role)
			.issuedAt(new Date(System.currentTimeMillis()))
			.expiration(new Date(System.currentTimeMillis() + expiredAt))
			.signWith(secretKey)
			.compact();

	}
}

```
```java
	//로그인 성공시 실행 메소드
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

		CustomUserDetails userDetails = (CustomUserDetails)authentication.getPrincipal();
		String username =  userDetails.getUsername();

		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
		Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
		GrantedAuthority auth = iterator.next();
		String role = auth.getAuthority();

		String token = jwtUtils.createToken(username,role,60*60*10L);

		// HTTP 인증 방식은 RFC7235 정의에 따라 아래 인증 헤더 형태를 가져야 한다.
		response.addHeader("Authorization", "Bearer " + token);

		log.info("Success Login");
	}

	//로그인 실패시 실행하는 메소드
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
		response.setStatus(401);
		log.info("Unsuccessful Login");
	}
```

SecurityConfig 
```java
		// 로그인 검증 필터 추가
		http
			// (어떤 필터 등록할지 , 등록할 위치를 어디로 할것인가)
			.addFilterAt(new LoginFilter(authenticationManager(configuration), jwtUtils), UsernamePasswordAuthenticationFilter.class)
		;
```
Header 값에 JWT 토큰이 잘 들어왔으면, 이제 모든 요청 Header 에 jwt 토큰을 넣어서 인증을 받는 방식을 통해 api 를 사용할 수 있게 할 것이다 <br>
ex) 알맞지 않은 토큰이 있으면 api 사용 불가, 올바른 토큰이면 api 요청 허용 <br>


### JWT 토큰에 대한 잠깐 세션을 만드는 jwt 필터
```java
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

```

### 세션 ID(=로그인ID) 및 Role 가져오기
```java
	@GetMapping("/")
	public String main() {
	    // LoginID
		String name = SecurityContextHolder.getContext().getAuthentication().getName();

		// Role
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
		Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
		GrantedAuthority auth = iterator.next();
		String role = auth.getAuthority();

		return "Main" + name;
	}
```


### CORS 설정 (리액트,스프링부트)
백엔드 단에서 cors 설정을 해야지, 앞단에서 데이터가 보여진다 <br>
cors 설정은 MVC Servlet 설정 및 Security 설정 2개를 해줘야한다.

Security 설정
```java
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
```

Servlet 설정
```java
@Configuration
public class WebConfig implements WebMvcConfigurer {

	// Spring Security 에서 swagger 를 불러오기 위한 Config 및 Cors 설정
	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/**")
			.allowedOrigins("*")
			.allowedOrigins("http://localhost:3000")
			.allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
			.allowedHeaders("*")
			.allowCredentials(false)
			.maxAge(3600L);
	}

}

```


프론트에서는 항상 헤더에 access_token 을 담아서 백엔드로 데이터 요청을 한다 <br>
백엔드에서는 그 토큰이 알맞은 토큰인지 검증을하고 올바른 토큰이면 데이터를 return 해준다 <br>

단순하게 JWT 를 발급하여 클라이언트 측으로 전송하면 인증/인가에 대한 주도권 자체가 클라이언트 측에 맡겨진다 <br>
JWT 를 탈취하여 서버측으로 접근할 경우 서버는 JWT 가 만료되기 전까지는 막을 수없다 <br>
프론트 측에서 로그아웃을 통해 토큰을 삭제해도 이미 토큰이 복제되어 있다면 피해를 입을 수 있다 <br>

이런 문제를 해결하기 위해서 refreshToken 을 서버 측 저장소에 기억  기억되어 있는 refreshToken  <br>
사용할 수 있도록 서버에서 주도권을 가질 수 있다 <br>

즉 refreshToken 발급시 db 에 저장, 갱신시 기존 refreshToken 삭제하고 새로운 토큰을 저장한다 <br>
1) redis, rdb 에 저장 -> redis 가 장점이 많으므로 redis 사용 추천

redis 는 TTL 설정을 통해 기한이 지난 refresh_token 을 자동으로 삭제 해준다 <br>

## 로그아웃
로그아웃 버튼 클릭 -> 로컬 스토리지에 존재하는 access_token 삭제  서버측 로그아웃 경로로 refreshToken 전송 <br>
로그아웃 로직을 추가하여 refreshToken 토큰을 받아 Cookie 초기화 후 Refresh DB 에서 해당 refreshToken 을 삭제한다 <br>
-> username 기반으로 모든 refreshToken 삭제한다 <br>

1) DB 리프레쉬 토큰 삭제
2) 리프레쉬 토큰 쿠키 삭제

스프링 시큐리티에서의 로그아웃 구현의 위치<br>
스프링 시큐리티 의존성을 추가하면 기본 로그아웃 기능이 활성화가 된 -> LogoutFilter 가 이미 정의되어 있다 <br>

```java

```
