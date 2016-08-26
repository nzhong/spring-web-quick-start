package com.learn.spring;

import com.learn.spring.provision.AppUser;
import com.learn.spring.repo.AppUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
public class LocalAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

	public static class Role implements GrantedAuthority {
		private final String roleName;
		public Role(String roleName) {
			this.roleName = roleName;
		}

		@Override
		public String getAuthority() {
			return roleName;
		}
	}

	@Autowired
	private AppUserRepository userRepo;

	@Autowired
	private PasswordEncoder encoder;

	@Override
	protected void additionalAuthenticationChecks(
		UserDetails userDetails,
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {
	}

	@Override
	protected UserDetails retrieveUser(
		String username,
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {

		String password = (String) usernamePasswordAuthenticationToken.getCredentials();
		List<AppUser> appUsers = userRepo.getByUsername(username);
		if ((appUsers == null) || appUsers.isEmpty()) {
			//logger.warn("Username {} password {}: appUser not found", username, password);
			throw new UsernameNotFoundException("Invalid Login");
		}
		AppUser appUser = appUsers.get(0);
		if (!encoder.matches(password, appUser.getPassword())) {
			//logger.warn("Username {} password {}: invalid password", username, password);
			throw new BadCredentialsException("Invalid Login");
		}

		List<GrantedAuthority> authorities = Arrays.asList( new Role("ADMIN") );
		return new User(username, password, authorities);
	}
}
