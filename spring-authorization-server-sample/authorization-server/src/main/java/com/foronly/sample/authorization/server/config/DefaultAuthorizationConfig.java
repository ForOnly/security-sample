package com.foronly.sample.authorization.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * <p>
 * </p>
 * <a href="https://docs.spring.io/spring-authorization-server/docs/current/reference/html/getting-started.html">spring
 * authorization server get start</a>
 *
 * @author li_cang_long
 * @since 2023/3/17 14:19
 */


@Configuration
public class DefaultAuthorizationConfig {

	/**
	 * A Spring Security filter chain for the Protocol Endpoints.
	 *
	 * @param http
	 * @return
	 * @throws Exception
	 */
	@Bean
	@Order
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		// OAuth2AuthorizationServerConfiguration是一个@Configuration，为OAuth2授权服务器提供最小的默认配置。
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http); // 将默认的OAuth2安全配置应用到HttpSecurity。
		// OAuth2AuthorizationServerConfiguration使用OAuth2AuthorizationServerConfigurer来应用默认配置，
		// 并注册了一个由支持OAuth2授权服务器的所有基础设施组件组成的SecurityFilterChain @Bean。
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.oidc(Customizer.withDefaults());    // Enable OpenID Connect 1.0
		http
				// Redirect to the login page when not authenticated from the
				// authorization endpoint
				.exceptionHandling((exceptions) -> exceptions
						.authenticationEntryPoint(
								new LoginUrlAuthenticationEntryPoint("/login"))
				)
				// Accept access tokens for User Info and/or Client Registration
				.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

		return http.build();
	}

	/**
	 * A Spring Security filter chain for authentication.
	 *
	 * @param http
	 * @return
	 * @throws Exception
	 */
	@Bean
	@Order
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {
		http
				.authorizeHttpRequests((authorize) -> authorize
						.anyRequest().authenticated()
				)
				// Form login handles the redirect to the login page from the
				// authorization server filter chain
				.formLogin(Customizer.withDefaults());

		return http.build();
	}

	/**
	 * An instance of UserDetailsService for retrieving users to authenticate.
	 * <p>
	 * authorization_code的授予需要资源所有者经过认证。因此，除了默认的OAuth2安全配置外，还必须配置一个用户认证机制。
	 * </p>
	 *
	 * @return
	 */
	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails userDetails = User.withDefaultPasswordEncoder()
									  .username("user")
									  .password("password")
									  .roles("USER")
									  .build();

		return new InMemoryUserDetailsManager(userDetails);
	}

	/**
	 * An instance of RegisteredClientRepository for managing clients.
	 *
	 * @return
	 */
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
															.clientId("messaging-client")
															.clientSecret("{noop}secret")
															.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
															.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
															.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
															.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
															.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
															.redirectUri("http://127.0.0.1:8080/authorized")
															.scope(OidcScopes.OPENID)
															.scope(OidcScopes.PROFILE)
															.scope("message.read")
															.scope("message.write")
															.clientSettings(ClientSettings.builder()
																						  .requireAuthorizationConsent(true)
																						  .build())
															.build();

		return new InMemoryRegisteredClientRepository(registeredClient);
	}

	/**
	 * An instance of com.nimbusds.jose.jwk.source.JWKSource for signing access tokens.
	 *
	 * @return
	 */
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair       keyPair    = generateRsaKey();
		RSAPublicKey  publicKey  = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	/**
	 * An instance of java.security.KeyPair with keys generated on startup used to create the JWKSource above.
	 *
	 * @return
	 */
	private static KeyPair generateRsaKey() {

		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	/**
	 * An instance of JwtDecoder for decoding signed access tokens.
	 *
	 * @param jwkSource
	 * @return
	 */
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	/**
	 * An instance of AuthorizationServerSettings to configure Spring Authorization Server.
	 *
	 * @return
	 */
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

}


