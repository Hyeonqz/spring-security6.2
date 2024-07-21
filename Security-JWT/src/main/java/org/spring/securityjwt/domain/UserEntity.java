package org.spring.securityjwt.domain;

import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@EntityListeners(AuditingEntityListener.class)
@Builder
@AllArgsConstructor @NoArgsConstructor
@Getter @Setter @ToString
@Entity(name="user")
public class UserEntity {

	@Id @GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String username;
	private String password;

	@Column(columnDefinition = "varchar(20)")
	@Enumerated(EnumType.STRING)
	private Role role;

	@CreatedDate
	private LocalDateTime createAt;

}
