package com.learn.spring.tokenauth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;


public class TokenUser implements Authentication {
	private static final long serialVersionUID = 7994154543730320720L;

	private final User user;
	private String token;

	private boolean authenticated = true;

	public TokenUser(final User user) {
		this.user = user;
	}

	public User getUser() {
		return user;
	}

	public String getToken() {
		return token;
	}
	public void setToken(String token) {
		this.token = token;
	}

	@Override
	public String getName() {
		return user.getUsername();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return user.getAuthorities();
	}

	@Override
	public Object getCredentials() {
		return user.getPassword();
	}

	@Override
	public User getDetails() {
		return user;
	}

	@Override
	public Object getPrincipal() {
		return user;
	}

	@Override
	public boolean isAuthenticated() {
		return authenticated;
	}

	@Override
	public void setAuthenticated(boolean authenticated) {
		this.authenticated = authenticated;
	}}