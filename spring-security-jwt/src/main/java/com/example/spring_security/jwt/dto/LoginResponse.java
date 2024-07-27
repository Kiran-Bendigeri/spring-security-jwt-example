package com.example.spring_security.jwt.dto;

import java.util.List;

import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Component
@NoArgsConstructor
@Getter
@Setter
public class LoginResponse {
	
	private String jwtToken;
	private String userName;
	private List<String> roles;
	
	public LoginResponse(String jwtToken, String userName, List<String> roles) {
		this.jwtToken=jwtToken;
		this.userName=userName;
		this.roles=roles;
	}
}
