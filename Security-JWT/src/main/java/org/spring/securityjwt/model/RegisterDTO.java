package org.spring.securityjwt.model;

import java.time.LocalDateTime;

import org.spring.securityjwt.domain.Role;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Builder
@Getter @Setter
public class RegisterDTO {

	@JsonProperty("login_id")
	private String username;
	private String password;
	private Role role;
}
