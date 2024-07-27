package com.example.spring_security.jwt.dto;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.annotation.JsonAlias;

import lombok.Getter;
import lombok.Setter;

@Component
@Getter
@Setter
public class LoginRequest {
	
	@JsonAlias("username")
	private String userName;
	private String password;
}
