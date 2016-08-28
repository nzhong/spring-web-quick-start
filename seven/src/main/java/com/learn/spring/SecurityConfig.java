package com.learn.spring;

import com.learn.spring.provision.AppUser;
import com.learn.spring.repo.AppUserRepository;
import com.learn.spring.saml.MySimpleUrlAuthenticationSuccessHandler;
import com.learn.spring.saml.MySAMLUserDetailsServiceImpl;
import com.learn.spring.tokenauth.TokenAuthenticationService;
import com.learn.spring.tokenauth.TokenUser;
import com.learn.spring.tokenauth.UserService;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.saml.*;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.*;
import org.springframework.security.web.*;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.*;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private AppUserRepository userRepo;

	@Autowired
	private LocalAuthenticationProvider localAuthenticationProvider;

	@Autowired
	private UserService userService;
	@Autowired
	private TokenAuthenticationService tokenAuthenticationService;

	@Autowired
	private MySAMLUserDetailsServiceImpl samlUserDetailsServiceImpl;

	// SAML Authentication Provider responsible for validating of received SAML
	// messages
	@Bean
	public SAMLAuthenticationProvider samlAuthenticationProvider() {
		SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
		samlAuthenticationProvider.setUserDetails(samlUserDetailsServiceImpl);
		samlAuthenticationProvider.setForcePrincipalAsString(false);
		return samlAuthenticationProvider;
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(localAuthenticationProvider);
		auth.authenticationProvider(samlAuthenticationProvider());
	}

	@Bean
	public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
		SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
		successLogoutHandler.setDefaultTargetUrl("/");
		return successLogoutHandler;
	}

	@Bean
	public SecurityContextLogoutHandler logoutHandler() {
		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.setInvalidateHttpSession(true);
		logoutHandler.setClearAuthentication(true);
		return logoutHandler;
	}

	@Bean
	public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
		return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
	}

	@Bean
	public SAMLLogoutFilter samlLogoutFilter() {
		return new SAMLLogoutFilter(successLogoutHandler(),
			new LogoutHandler[] { logoutHandler() },
			new LogoutHandler[] { logoutHandler() });
	}

	@Bean
	public SimpleUrlAuthenticationSuccessHandler successRedirectHandler() {
		SimpleUrlAuthenticationSuccessHandler successRedirectHandler = new MySimpleUrlAuthenticationSuccessHandler(userService, tokenAuthenticationService);
		successRedirectHandler.setDefaultTargetUrl("/index.html");
		return successRedirectHandler;
	}

	@Bean
	public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
		SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
		failureHandler.setUseForward(true);
		failureHandler.setDefaultFailureUrl("/error");
		return failureHandler;
	}

	@Bean
	public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
		SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
		samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
		samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
		samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
		return samlWebSSOProcessingFilter;
	}

	@Bean
	public FilterChainProxy samlFilter() throws Exception {
		List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"), samlLogoutFilter()));
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"), metadataDisplayFilter()));
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"), samlWebSSOProcessingFilter()));
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSOHoK/**"), samlWebSSOHoKProcessingFilter()));
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"), samlLogoutProcessingFilter()));
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"), samlIDPDiscovery()));

		return new FilterChainProxy(chains);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class);
		http.addFilterAfter(samlFilter(), BasicAuthenticationFilter.class);
		http.addFilterBefore(new AppCustomFilter(tokenAuthenticationService), UsernamePasswordAuthenticationFilter.class);
		http.csrf().disable();
		http.authorizeRequests().antMatchers("/spring/**").authenticated();
		http.authorizeRequests().anyRequest().permitAll();

		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		http.formLogin().successHandler(new AuthenticationSuccessHandler() {
			@Override
			public void onAuthenticationSuccess(
					HttpServletRequest request,
					HttpServletResponse response,
					org.springframework.security.core.Authentication authentication) throws IOException, ServletException {

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

	// XML parser pool needed for OpenSAML parsing
	@Bean(initMethod = "initialize")
	public StaticBasicParserPool parserPool() {
		return new StaticBasicParserPool();
	}

	@Bean(name = "parserPoolHolder")
	public ParserPoolHolder parserPoolHolder() {
		return new ParserPoolHolder();
	}

	@Bean
	public static SAMLBootstrap sAMLBootstrap() {
		return new SAMLBootstrap();
	}

	@Bean
	public SAMLContextProviderImpl contextProvider() {
		SAMLContextProviderLB samlContextProviderImpl = new SAMLContextProviderLB();
		samlContextProviderImpl.setScheme("http");
		samlContextProviderImpl.setServerName("localhost");
		samlContextProviderImpl.setServerPort(9007);
		samlContextProviderImpl.setIncludeServerPortInRequestURL(true);
		samlContextProviderImpl.setContextPath("/");
		return samlContextProviderImpl;
	}

	@Bean
	@Qualifier("idp-okta")
	public ExtendedMetadataDelegate ssoOktaExtendedMetadataProvider() throws MetadataProviderException {
		FilesystemMetadataProvider fileMetadataProvider;
		try {
			fileMetadataProvider = new FilesystemMetadataProvider(new ClassPathResource("/saml/test-idp.xml").getFile());
		} catch (IOException e) {
			e.printStackTrace();
			throw new MetadataProviderException(e.getMessage());
		}
		fileMetadataProvider.setParserPool(parserPool());
		ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(fileMetadataProvider, extendedMetadata());

		extendedMetadataDelegate.setMetadataTrustCheck(false);
		extendedMetadataDelegate.setMetadataRequireSignature(false);
		return extendedMetadataDelegate;
	}

	@Bean
	@Qualifier("metadata")
	public CachingMetadataManager metadata() throws MetadataProviderException {
		List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
		providers.add(ssoOktaExtendedMetadataProvider());
		return new CachingMetadataManager(providers);
	}

	// Logger for SAML messages and events
	@Bean
	public SAMLDefaultLogger samlLogger() {
		return new SAMLDefaultLogger();
	}

	// SAML 2.0 WebSSO Assertion Consumer
	@Bean
	public WebSSOProfileConsumer webSSOprofileConsumer() {
		return new WebSSOProfileConsumerImpl();
	}

	// SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
	@Bean
	public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
		return new WebSSOProfileConsumerHoKImpl();
	}

	// SAML 2.0 Web SSO profile
	@Bean
	public WebSSOProfile webSSOprofile() {
		return new WebSSOProfileImpl();
	}

	// SAML 2.0 Holder-of-Key Web SSO profile
	@Bean
	public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
		return new WebSSOProfileConsumerHoKImpl();
	}

	// SAML 2.0 ECP profile
	@Bean
	public WebSSOProfileECPImpl ecpprofile() {
		return new WebSSOProfileECPImpl();
	}

	@Bean
	public SingleLogoutProfile logoutprofile() {
		return new SingleLogoutProfileImpl();
	}

	// Central storage of cryptographic keys
	@Bean
	public KeyManager keyManager() {
		DefaultResourceLoader loader = new DefaultResourceLoader();
		Resource storeFile = loader.getResource("classpath:/saml/samlKeystore.jks");
		String storePass = "changeit";
		Map<String, String> passwords = new HashMap<String, String>();
		passwords.put("mydomain", "changeit");
		String defaultKey = "mydomain";
		return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
	}

	// Setup TLS Socket Factory
	@Bean
	public TLSProtocolConfigurer tlsProtocolConfigurer() {
		return new TLSProtocolConfigurer();
	}

	@Bean
	public ProtocolSocketFactory socketFactory() {
		return new TLSProtocolSocketFactory(keyManager(), null, "default");
	}

	@Bean
	public Protocol socketFactoryProtocol() {
		return new Protocol("https", socketFactory(), 443);
	}

	@Bean
	public MethodInvokingFactoryBean socketFactoryInitialization() {
		MethodInvokingFactoryBean methodInvokingFactoryBean = new MethodInvokingFactoryBean();
		methodInvokingFactoryBean.setTargetClass(Protocol.class);
		methodInvokingFactoryBean.setTargetMethod("registerProtocol");
		Object[] args = { "https", socketFactoryProtocol() };
		methodInvokingFactoryBean.setArguments(args);
		return methodInvokingFactoryBean;
	}

	// Setup advanced info about metadata
	@Bean
	public ExtendedMetadata extendedMetadata() {
		ExtendedMetadata extendedMetadata = new ExtendedMetadata();
		extendedMetadata.setIdpDiscoveryEnabled(true);
		extendedMetadata.setSignMetadata(true);
		return extendedMetadata;
	}

	// IDP Discovery Service
	@Bean
	public SAMLDiscovery samlIDPDiscovery() {
		SAMLDiscovery idpDiscovery = new SAMLDiscovery();
		idpDiscovery.setIdpSelectionPath("/saml/idpSelection");
		return idpDiscovery;
	}

	// The filter is waiting for connections on URL suffixed with filterSuffix
	// and presents SP metadata there
	@Bean
	public MetadataDisplayFilter metadataDisplayFilter() {
		return new MetadataDisplayFilter();
	}

	@Bean
	public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
		SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = new SAMLWebSSOHoKProcessingFilter();
		samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
		samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager());
		samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
		return samlWebSSOHoKProcessingFilter;
	}

	@Bean
	public MetadataGenerator metadataGenerator() {
		MetadataGenerator metadataGenerator = new MetadataGenerator();
		metadataGenerator.setEntityId("SPRING-QUICK-START"); // "NZ TEST APP 1");
		metadataGenerator.setExtendedMetadata(extendedMetadata());
		metadataGenerator.setIncludeDiscoveryExtension(false);
		metadataGenerator.setKeyManager(keyManager());

		metadataGenerator.setEntityBaseURL("http://localhost:9007");
		return metadataGenerator;
	}

	@Bean
	public MetadataGeneratorFilter metadataGeneratorFilter() {
		return new MetadataGeneratorFilter(metadataGenerator());
	}

	// Initialization of the velocity engine
	@Bean
	public VelocityEngine velocityEngine() {
		return VelocityFactory.getEngine();
	}

	@Bean
	public HTTPSOAP11Binding soapBinding() {
		return new HTTPSOAP11Binding(parserPool());
	}

	@Bean
	public HTTPPostBinding httpPostBinding() {
		return new HTTPPostBinding(parserPool(), velocityEngine());
	}

	@Bean
	public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
		return new HTTPRedirectDeflateBinding(parserPool());
	}

	@Bean
	public HTTPSOAP11Binding httpSOAP11Binding() {
		return new HTTPSOAP11Binding(parserPool());
	}

	@Bean
	public HTTPPAOS11Binding httpPAOS11Binding() {
		return new HTTPPAOS11Binding(parserPool());
	}

	// Processor
	@Bean
	public SAMLProcessorImpl processor() {
		Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
		bindings.add(httpRedirectDeflateBinding());
		bindings.add(httpPostBinding());
		// bindings.add(artifactBinding(parserPool(), velocityEngine()));
		bindings.add(httpSOAP11Binding());
		bindings.add(httpPAOS11Binding());
		return new SAMLProcessorImpl(bindings);
	}

}