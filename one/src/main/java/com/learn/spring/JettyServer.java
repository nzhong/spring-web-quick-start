package com.learn.spring;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JettyServer {

	public static class BlockingServlet extends HttpServlet
	{
		@Override
		protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
		{
			try {
				resp.getWriter().write( "JettyServer" );
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public static void main(String[] args) throws Exception
	{
		Server server = new Server(9001);

		ServletContextHandler context = new ServletContextHandler();
		context.setContextPath("/");
		ServletHolder blockingHolder = context.addServlet(BlockingServlet.class,"/serv");

		server.setHandler(context);
		server.start();
		server.join();
	}
}
