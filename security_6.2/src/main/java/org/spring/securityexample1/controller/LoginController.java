package org.spring.securityexample1.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import ch.qos.logback.core.model.Model;

@Controller
public class LoginController {

	@GetMapping("/login")
	public String loginP() {
		return "login";
	}

/*	@PostMapping("/loginProc")
	public String loginProc(@RequestParam String username, @RequestParam String password) {
		return "redirect:/admin";
	}*/

}
