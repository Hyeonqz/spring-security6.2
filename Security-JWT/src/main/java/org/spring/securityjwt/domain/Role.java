package org.spring.securityjwt.domain;

import lombok.Getter;

@Getter
public enum Role {
	USER("ROLE_USER"),
	ADMIN("ROLE_ADMIN")
	;

	Role (String description) {
		this.description = description;
	}

	private String description;
}
