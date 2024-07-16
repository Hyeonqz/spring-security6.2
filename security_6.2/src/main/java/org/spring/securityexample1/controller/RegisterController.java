package org.spring.securityexample1.controller;

import org.spring.securityexample1.dto.MemberDTO;
import org.spring.securityexample1.service.RegisterService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Controller
public class RegisterController {
	private final RegisterService registerService;

	@GetMapping("/join")
	public String register(){
		return "MemberRegister";
	}

	@PostMapping("/joinProc")
	public String joinProc(MemberDTO memberDTO){
		registerService.register(memberDTO);

		return "redirect:/login";
	}
}
