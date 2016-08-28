package com.learn.spring.saml;

import com.learn.spring.LocalAuthenticationProvider;
import com.learn.spring.repo.AppUserRepository;
import org.opensaml.saml2.core.impl.AssertionImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class MySAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

	@Autowired
	private MongoOperations operations;
	@Autowired
	private AppUserRepository userRepo;

	@Override
	public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {

		AssertionImpl ai = (AssertionImpl) credential.getAuthenticationAssertion();

		String incomingSamlId = credential.getNameID().getValue();
		System.out.println("SAML user logged in. incomingSamlId = " + incomingSamlId);

		final String idpIssuer = credential.getRemoteEntityID();
		System.out.println("SAML user logged in. idpIssuer = " + idpIssuer);

		List<GrantedAuthority> authorities = Arrays.asList( new LocalAuthenticationProvider.Role("ADMIN") );
		return new User(incomingSamlId, "", authorities);
	}
}