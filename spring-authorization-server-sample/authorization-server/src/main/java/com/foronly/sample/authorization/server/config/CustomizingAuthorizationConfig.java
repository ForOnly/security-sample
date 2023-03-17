package com.foronly.sample.authorization.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;

/**
 * <p>
 *
 * </p>
 * <a
 * href="https://docs.spring.io/spring-authorization-server/docs/current/reference/html/configuration-model.html#customizing-the-configuration"></a>
 *
 * @author li_cang_long
 * @since 2023/3/17 15:00
 */
@Configuration
public class CustomizingAuthorizationConfig {


	@Bean
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer();
		http.apply(authorizationServerConfigurer);

		authorizationServerConfigurer
				.registeredClientRepository(new InMemoryRegisteredClientRepository())
				.authorizationService(new InMemoryOAuth2AuthorizationService())
				.authorizationConsentService(new InMemoryOAuth2AuthorizationConsentService())
				.authorizationServerSettings(new DefaultAuthorizationConfig().authorizationServerSettings())
				.tokenGenerator(new DelegatingOAuth2TokenGenerator())
				.clientAuthentication(clientAuthentication -> {
				})
				.authorizationEndpoint(authorizationEndpoint -> {
				})
				.tokenEndpoint(tokenEndpoint -> {
				})
				.tokenIntrospectionEndpoint(tokenIntrospectionEndpoint -> {
				})
				.tokenRevocationEndpoint(tokenRevocationEndpoint -> {
				})
				.authorizationServerMetadataEndpoint(authorizationServerMetadataEndpoint -> {
				})
				.oidc(oidc -> oidc
						.providerConfigurationEndpoint(providerConfigurationEndpoint -> {
						})
						.userInfoEndpoint(userInfoEndpoint -> {
						})
						.clientRegistrationEndpoint(clientRegistrationEndpoint -> {
						})
				);

		return http.build();
	}


	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		InMemoryRegisteredClientRepository clientRepository = new InMemoryRegisteredClientRepository();
		return clientRepository;
	}
}
