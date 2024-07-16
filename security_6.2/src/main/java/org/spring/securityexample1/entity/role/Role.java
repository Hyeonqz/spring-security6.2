package org.spring.securityexample1.entity.role;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum Role {

	ADMIN("ROLE_ADMIN"),
	USER("ROLE_USER"),
	;

	private String description;
}
