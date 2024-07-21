package org.spring.securityjwt.domain;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
	Boolean existsByUsername(String username);
	UserEntity findByUsername(String username);
}
