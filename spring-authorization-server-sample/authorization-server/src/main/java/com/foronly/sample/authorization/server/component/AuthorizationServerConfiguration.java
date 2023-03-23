package com.foronly.sample.authorization.server.component;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * <p>
 *
 * </p>
 *
 * @author li_cang_long
 * @since 2023/3/18 10:48
 */
@Configuration
public class AuthorizationServerConfiguration {

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		return new InMemoryRegisteredClientRepository();
	}

	@Bean
	public OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService() {
		return new InMemoryOAuth2AuthorizationConsentService();
	}

	@Bean
	public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {
		return new DelegatingOAuth2TokenGenerator();
	}
}
