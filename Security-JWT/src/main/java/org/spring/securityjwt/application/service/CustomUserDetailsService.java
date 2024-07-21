package org.spring.securityjwt.application.service;

import java.util.Optional;

import org.spring.securityjwt.domain.UserEntity;
import org.spring.securityjwt.domain.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

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
