package com.learn.spring;

import org.eclipse.jetty.annotations.AnnotationConfiguration;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ConcurrentHashSet;
import org.eclipse.jetty.webapp.Configuration;
import org.eclipse.jetty.webapp.WebAppContext;
import org.springframework.web.WebApplicationInitializer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;

public class JettySpringServer {

	public static class BlockingServlet extends HttpServlet
	{
		@Override
		protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
		{
			try {
				resp.getWriter().write( "JettySpringServer" );
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public static void main(String[] args) throws Exception
	{
		Server server = new Server(9007);

		final WebAppContext context = new WebAppContext();
		context.setContextPath("/");
		context.addServlet(BlockingServlet.class,"/serv");

		context.setConfigurations(new Configuration[] { new AnnotationConfiguration() {
			@Override
			public void preConfigure(WebAppContext context) throws Exception {
				final ClassInheritanceMap map = new ClassInheritanceMap();
				final ConcurrentHashSet<String> s = new ConcurrentHashSet<String>();
				s.add(ServletInitializer.class.getName());
				map.put(WebApplicationInitializer.class.getName(), s);
				context.setAttribute(CLASS_INHERITANCE_MAP, map);
			}
		} });

		server.setHandler(context);
		server.start();
		server.join();
	}
}
