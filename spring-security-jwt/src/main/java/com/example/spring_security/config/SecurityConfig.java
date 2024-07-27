package com.example.spring_security.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.spring_security.jwt.AuthEntryPointJwt;
import com.example.spring_security.jwt.JwtAuthFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
	@Autowired
	private AuthEntryPointJwt unAuthorizedHandler;
	
	@Autowired
	private DataSource dataSource;

	@Bean
	public JwtAuthFilter authFilter() {
		return new JwtAuthFilter();
	}
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(
			authorize -> authorize.requestMatchers("/h2-console/**", "/sign-in").permitAll()
			.anyRequest().authenticated())
			.csrf(AbstractHttpConfigurer::disable)
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.httpBasic(Customizer.withDefaults())
			.headers(header -> header.frameOptions(frame -> frame.sameOrigin()))
			.exceptionHandling(exception -> exception.authenticationEntryPoint(unAuthorizedHandler))
			.addFilterBefore(authFilter(), UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}
	
	
	@Bean
	public UserDetailsService getUserDetails() {
		return new JdbcUserDetailsManager(dataSource);
	}
	
	@Bean
	public CommandLineRunner init(UserDetailsService userDetailsService) {
		return args -> {
			JdbcUserDetailsManager userDetailsManager = (JdbcUserDetailsManager) userDetailsService;
			UserDetails user1 = User.withUsername("user")
			.password(encoder().encode("user"))
			.roles("ADMIN")
			.build();
			userDetailsManager.createUser(user1);
		};
	}
	
	@Bean
	public BCryptPasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthenticationManager authManager(AuthenticationConfiguration builder) throws Exception {
	  return builder.getAuthenticationManager();
	}
	 

}
