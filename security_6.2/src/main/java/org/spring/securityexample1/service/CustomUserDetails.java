package org.spring.securityexample1.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.spring.securityexample1.entity.MemberEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomUserDetails implements UserDetails {

	/*
	* 로그인 검증을 처리하는 로직이다.
	* */
	private final MemberEntity memberEntity;

	public CustomUserDetails (MemberEntity memberEntity) {
		this.memberEntity = memberEntity;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities () {
		Collection<GrantedAuthority> collection = new ArrayList<>();

		collection.add(new GrantedAuthority() {
			@Override
			public String getAuthority () {
				System.out.println(memberEntity.getRole());
				return memberEntity.getRole().getDescription();
			}
		});

		return collection;
	}

	@Override
	public String getPassword () {
		return memberEntity.getPassword();
	}

	@Override
	public String getUsername () {
		return memberEntity.getUsername();
	}

	// 아래 4가지 메소드는 회원가입시 Role 을 하나를 더 줘야 한다.
	// 만약 이 부분을 검증하는 로직을 처리하려면 DB 테이블에 아래 값들을 체크하는 필드(=컬럼)이 존재 해야 한다.
	@Override
	public boolean isAccountNonExpired () {
		return true;
	}

	@Override
	public boolean isAccountNonLocked () {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired () {
		return true;
	}

	@Override
	public boolean isEnabled () {
		return true;
	}

}
