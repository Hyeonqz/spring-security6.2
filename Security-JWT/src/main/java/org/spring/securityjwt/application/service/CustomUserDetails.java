package org.spring.securityjwt.application.service;

import java.util.ArrayList;
import java.util.Collection;

import org.spring.securityjwt.domain.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.RequiredArgsConstructor;

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
