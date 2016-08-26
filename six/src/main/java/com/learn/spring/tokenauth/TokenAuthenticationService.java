package com.learn.spring.tokenauth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;


@Service
public class TokenAuthenticationService {

	@Autowired
	private UserService userService;

	private final String secret = "tooManySecrets";

	public static final String AUTH_HEADER_NAME = "X-AUTH-TOKEN";

	public TokenUser getAuthentication(final HttpServletRequest request) throws Exception {
		final String token = request.getHeader(AUTH_HEADER_NAME);
		if (token != null && !token.isEmpty()) {
			String username = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody().getSubject();
			return userService.loadUserByUsername(username);
		}
		return null;
	}

	public String createTokenForUser(TokenUser user) {
		return Jwts.builder().setSubject(user.getName()).signWith(SignatureAlgorithm.HS512, secret).compact();
	}
}
