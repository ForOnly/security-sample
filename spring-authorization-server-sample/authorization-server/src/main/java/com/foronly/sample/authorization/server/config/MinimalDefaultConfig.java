package com.foronly.sample.authorization.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * <p>
 *
 * </p>
 * <a
 * href="https://docs.spring.io/spring-authorization-server/docs/current/reference/html/configuration-model.html#default-configuration"></a>
 *
 * @author li_cang_long
 * @since 2023/3/17 14:48
 */

// @Configuration
//自动注册了一个AuthorizationServerSettings, 为授权服务器提供最小的默认配置
// @Import(OAuth2AuthorizationServerConfiguration.class)
public class MinimalDefaultConfig {

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		List<RegisteredClient> registrations = new ArrayList<>();
		// 注册客户端信息
		// ......
		return new InMemoryRegisteredClientRepository(registrations);
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair       keyPair    = generateRsaKey();
		RSAPublicKey  publicKey  = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		com.nimbusds.jose.jwk.RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

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

}