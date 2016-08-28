package com.learn.spring.saml;


import com.learn.spring.tokenauth.TokenAuthenticationService;
import com.learn.spring.tokenauth.TokenUser;
import com.learn.spring.tokenauth.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class MySimpleUrlAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
	private UserService userService;
	private TokenAuthenticationService tokenAuthenticationService;

	public MySimpleUrlAuthenticationSuccessHandler(final UserService userService, final TokenAuthenticationService tokenAuthenticationService) {
		this.userService = userService;
		this.tokenAuthenticationService = tokenAuthenticationService;
	}

	@Override
	public void onAuthenticationSuccess(
		HttpServletRequest request,
		HttpServletResponse response,
		Authentication authentication) throws IOException, ServletException {

		// super.onAuthenticationSuccess(request, response, authentication);
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
			if (response.isCommitted()) {
				return;
			}
		}

		User u = (User) authentication.getPrincipal();
		TokenUser tu = new TokenUser(u);
		userService.addUser(tu);
		String xAuthToken = tokenAuthenticationService.createTokenForUser(tu);

		response.setContentType("text/html");
		response.setStatus(HttpServletResponse.SC_OK);
		StringBuilder buf = new StringBuilder();
		buf.append("<html><head><title>Login Success</title></head>");
		buf.append("<script>");
		buf.append(" function saveToken() { localStorage.setItem('X-AUTH-TOKEN', '" + xAuthToken + "'); } ");
		buf.append("</script>");
		buf.append("<body onload=\"saveToken();\">"+xAuthToken+"</body></html>");
		response.getWriter().println(buf.toString());

		HttpSession currSession = request.getSession(false);
		if (currSession != null) {
			currSession.invalidate();
		}
		SecurityContextHolder.clearContext();
	}
}