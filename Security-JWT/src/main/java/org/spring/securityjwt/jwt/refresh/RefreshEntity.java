package org.spring.securityjwt.jwt.refresh;

import java.time.LocalDateTime;
import java.util.Date;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;

@Data
@Entity(name="refresh_token")
public class RefreshEntity {

	@Id @GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String username;
	private String refresh;
	private Date expiredAt;

}
