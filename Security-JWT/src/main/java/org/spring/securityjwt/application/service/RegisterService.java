package org.spring.securityjwt.application.service;

import java.time.LocalDateTime;

import org.spring.securityjwt.domain.Role;
import org.spring.securityjwt.domain.UserEntity;
import org.spring.securityjwt.domain.UserRepository;
import org.spring.securityjwt.model.RegisterDTO;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;

@Transactional(readOnly = true)
@RequiredArgsConstructor
@Service
public class RegisterService {
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder passwordEncoder;

	@Transactional
	public RegisterDTO register(RegisterDTO registerDTO) {
		String loginId = registerDTO.getUsername();
		String password = registerDTO.getPassword();

		Boolean isExist = userRepository.existsByUsername(loginId);

		if(isExist) {
			throw new RuntimeException("동일한 ID가 존재합니다");
		}

		UserEntity user = new UserEntity();
		user.setUsername(loginId);
		user.setPassword(passwordEncoder.encode(password));
		user.setRole(Role.USER);
		user.setCreateAt(LocalDateTime.now());

		userRepository.save(user);

		return RegisterDTO.builder()
			.username(user.getUsername())
			.password(user.getPassword())
			.role(user.getRole())
			.build();

	}
}
