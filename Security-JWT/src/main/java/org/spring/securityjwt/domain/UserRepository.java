package org.spring.securityjwt.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
	Boolean existsByLoginId(String loginId);
}
