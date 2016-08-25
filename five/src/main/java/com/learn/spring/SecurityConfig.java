package com.learn.spring;

import com.learn.spring.provision.AppUser;
import com.learn.spring.repo.AppUserRepository;
import org.eclipse.jetty.server.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.List;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private AppUserRepository userRepo;

	@Autowired
	private LocalAuthenticationProvider authenticationProvider;

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.csrf().disable();
		http.authorizeRequests().antMatchers("/spring/**").authenticated();
		http.authorizeRequests().anyRequest().permitAll();

		http.formLogin().successHandler(new AuthenticationSuccessHandler() {
			@Override
			public void onAuthenticationSuccess(
					HttpServletRequest request,
					HttpServletResponse response,
					org.springframework.security.core.Authentication authentication) throws IOException, ServletException {
				new DefaultRedirectStrategy().sendRedirect(request, response, "/spring/status");
			}
		}).permitAll();
		http.logout().permitAll();

		// doesn't really belong here, but let's seed one user
		List<AppUser> appUsers = userRepo.getByUsername("test");
		if ( appUsers==null || appUsers.isEmpty() ) {
			// "$2a$10$RTa88yBTzHpAcPutD2puxunAzj9hYMgA5yXTclgcV1xz5Szs3Jq8i" is "test" encoded
			AppUser appUser = new AppUser("test", "$2a$10$RTa88yBTzHpAcPutD2puxunAzj9hYMgA5yXTclgcV1xz5Szs3Jq8i");
			userRepo.save(appUser);
		}
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}