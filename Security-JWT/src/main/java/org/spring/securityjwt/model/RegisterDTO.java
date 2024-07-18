package org.spring.securityjwt.model;

import java.time.LocalDateTime;

import org.spring.securityjwt.domain.Role;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Builder
@Getter @Setter
public class RegisterDTO {

	private String loginId;
	private String password;
	private Role role;
}
