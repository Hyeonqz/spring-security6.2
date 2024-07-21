package org.spring.securityjwt.ui;

import org.spring.securityjwt.jwt.JwtService;
import org.spring.securityjwt.jwt.JwtUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequestMapping("/api")
@RequiredArgsConstructor
@RestController
public class reIssueController {
	private final JwtService jwtService;

	@PostMapping("/reissue")
	public void reissue(HttpServletRequest request, HttpServletResponse response) {
		jwtService.issueRefreshToken(request,response);
	}


}
