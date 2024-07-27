package com.example.spring_security.jwt;

import java.security.Key;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.Setter;

@Component
@Getter
@Setter
@ConfigurationProperties(prefix = "spring.security.jwt.token")
public class JwtUtils {

	public static Logger logger = LoggerFactory.getLogger(JwtUtils.class);

	private String secreatToken;

	private long tokenExpiration;

	public String getJwtFromHeader(HttpServletRequest request) {
		final String bearerToken = request.getHeader("Authorization");
		logger.debug("Authorization Header {}", bearerToken);
		return (bearerToken != null && bearerToken.startsWith("Bearer ")) ? 
				bearerToken.substring("Bearer ".length()) : null;
	}

	public String generateTokenFromUsername(UserDetails userDetails) {
		final String username = userDetails.getUsername();
		return Jwts.builder()
				.subject(username)
				.issuedAt(new Date())
				.expiration(new Date(new Date().getTime() + TimeUnit.MINUTES.toMillis(tokenExpiration) ))
				.signWith(key())
				.compact();
	}

	public String getUsernameFromJwtToken(String token) {
		return Jwts.parser()
				.verifyWith((SecretKey) key())
				.build().parseSignedClaims(token)
				.getPayload().getSubject();
	}

	private Key key() {
		return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secreatToken));
	}

	public boolean validateJwtToken(String token) {
		try {
			Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(token).getPayload().getSubject();
			return true;
		} catch (MalformedJwtException me) {
			logger.debug("Malformed Jwt token {}", me.getMessage());
		} catch (ExpiredJwtException ee) {
			logger.debug("Expired Jwt {}", ee.getMessage());
		} catch (UnsupportedJwtException ue) {
			logger.debug("Unsupported Jwt {}", ue.getMessage());
		} catch (IllegalArgumentException ie) {
			logger.debug("Illegal argument {}", ie.getMessage());
		}

		return false;
	}

}
