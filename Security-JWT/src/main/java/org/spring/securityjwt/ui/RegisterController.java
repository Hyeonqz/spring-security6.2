package org.spring.securityjwt.ui;

import org.spring.securityjwt.application.service.RegisterService;
import org.spring.securityjwt.model.RegisterDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RequestMapping("/api")
@RestController
public class RegisterController {
	private final RegisterService registerService;

	@PostMapping("/register")
	public ResponseEntity<RegisterDTO> joinProcess(@RequestBody RegisterDTO registerDTO) {
		RegisterDTO register = registerService.register(registerDTO);
		return ResponseEntity.ok(register);
	}

}
