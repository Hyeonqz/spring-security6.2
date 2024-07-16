package org.spring.securityexample1.service;

import org.spring.securityexample1.entity.MemberEntity;
import org.spring.securityexample1.repository.MemberEntityRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class CustomUserDetailService implements UserDetailsService {
	private final MemberEntityRepository memberEntityRepository;

	@Override
	public UserDetails loadUserByUsername (String username) throws UsernameNotFoundException {

		MemberEntity byUsername = memberEntityRepository.findByUsername(username);

		if(byUsername != null) {
			return new CustomUserDetails(byUsername);
		}

		return null;
	}

}
