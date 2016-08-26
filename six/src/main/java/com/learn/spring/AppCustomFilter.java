package com.learn.spring;

import com.learn.spring.tokenauth.TokenAuthenticationService;
import com.learn.spring.tokenauth.TokenUser;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class AppCustomFilter extends GenericFilterBean {

	private TokenAuthenticationService tokenAuthenticationService;
	public AppCustomFilter(final TokenAuthenticationService tokenAuthenticationService) {
		this.tokenAuthenticationService = tokenAuthenticationService;
	}

	@Override
	public void doFilter(
		ServletRequest request,
		ServletResponse response,
		FilterChain chain) throws IOException, ServletException {

		if (request instanceof ServletRequest)
		{
			HttpServletRequest httpRequest = HttpServletRequest.class.cast(request);
			TokenUser loginUser = null;
			try {
				loginUser = tokenAuthenticationService.getAuthentication(httpRequest);
			}
			catch(Exception e) {
				loginUser = null;
			}

			if ( loginUser == null ) { // user is not authenticated, we may need to throw exception
				if ( httpRequest.getRequestURI().indexOf("login")<0 ) {
					throw new ServletException("Invalid authentication when accessing "+httpRequest.getRequestURI());
				}
			}
			else {
				SecurityContextHolder.getContext().setAuthentication(loginUser);
			}
		}
		chain.doFilter(request, response);
	}
}
