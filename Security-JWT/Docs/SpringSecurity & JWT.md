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

### 회원가입
```java
public interface UserRepository extends JpaRepository<UserEntity, Long> {
	Boolean existsByLoginId(String loginId);
}
```
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
