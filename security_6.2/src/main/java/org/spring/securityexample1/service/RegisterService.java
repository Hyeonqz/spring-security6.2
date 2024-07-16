package org.spring.securityexample1.service;

import org.spring.securityexample1.dto.MemberDTO;
import org.spring.securityexample1.entity.MemberEntity;
import org.spring.securityexample1.entity.role.Role;
import org.spring.securityexample1.repository.MemberEntityRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Service
public class RegisterService {
	private final MemberEntityRepository memberEntityRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	public void register(MemberDTO memberDTO) {
		boolean isUser = memberEntityRepository.existsByUsername(memberDTO.getUsername());
		if(isUser) {
			throw new RuntimeException("이미 존재하는 회원 입니다.");
		}

		MemberEntity member = new MemberEntity();
		member.setUsername(memberDTO.getUsername());
		member.setPassword(bCryptPasswordEncoder.encode(memberDTO.getPassword()));
		member.setRole(Role.ADMIN);

		memberEntityRepository.save(member);
	}
}
