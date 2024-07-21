package org.spring.securityjwt.ui;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/admin")
@RestController
public class AdminController {

	@GetMapping()
	public String admin() {
		String name = SecurityContextHolder.getContext().getAuthentication().getName();
		return "Hello Admin?" + name;
	}
}
