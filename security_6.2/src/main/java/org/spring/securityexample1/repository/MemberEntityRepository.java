package org.spring.securityexample1.repository;

import org.spring.securityexample1.entity.MemberEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberEntityRepository extends JpaRepository<MemberEntity, Long> {
	Boolean existsByUsername(String username);
	MemberEntity findByUsername(String username);
}
