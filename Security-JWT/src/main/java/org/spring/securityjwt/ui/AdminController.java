package org.spring.securityjwt.ui;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/admin")
@RestController
public class AdminController {

	@GetMapping("/")
	public String admin() {
		return "Admin";
	}
}
