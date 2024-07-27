package com.example.spring_security.controller;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.spring_security.jwt.JwtUtils;
import com.example.spring_security.jwt.dto.LoginRequest;
import com.example.spring_security.jwt.dto.LoginResponse;

@RestController
public class JwtController {
	
	private Logger logger = LoggerFactory.getLogger(JwtController.class);
	
	@Autowired
	private JwtUtils jwtUtils;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@PostMapping("/sign-in")
	public ResponseEntity<?> signIn(@RequestBody LoginRequest loginRequest) {
		
		Authentication authentication;
		logger.debug("sign-in start {}", new Date());
		try {
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(loginRequest.getUserName(), loginRequest.getPassword());
			authentication = authenticationManager.authenticate(token);
			logger.debug("sign-in end {}", new Date());
		}catch (AuthenticationException e) {
			logger.debug("Sign-In failed {}", e.getMessage());
			Map<String, Object> map = new HashMap<>();
			map.put("Bad Request", HttpStatus.BAD_REQUEST);
			map.put("Username not found", loginRequest.getUserName());
			return new ResponseEntity<>(map, HttpStatus.BAD_REQUEST);
		}
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		UserDetails userDetils = (UserDetails)authentication.getPrincipal();
		
		String jwtToken = jwtUtils.generateTokenFromUsername(userDetils);
		List<String> roles = userDetils.getAuthorities()
				.stream().map(authority -> authority.toString())
				.collect(Collectors.toList());
		
		LoginResponse loginResponse = new LoginResponse(jwtToken, userDetils.getUsername(), roles);
		return ResponseEntity.ok(loginResponse);
	}
	
	@GetMapping("/login")
	@PreAuthorize("hasRole('ADMIN')")
	public String login() {
		return "login";
	}

}
