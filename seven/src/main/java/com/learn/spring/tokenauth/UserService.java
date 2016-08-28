package com.learn.spring.tokenauth;

import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Service
public class UserService {
	private final Map<String, TokenUser> userMap = new HashMap<String, TokenUser>();;
	public UserService() {}

	public TokenUser loadUserByUsername(final String username) throws Exception {
		final TokenUser user = userMap.get(username);
		if (user == null) {
			throw new Exception("user not found");
		}
		return user;
	}

	public void addUser(TokenUser user) {
		userMap.put(user.getName(), user);
	}
}
