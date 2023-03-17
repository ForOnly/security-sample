# spring-authorization-server-sample

## 入门

### OAuth2AuthorizationServerConfiguration

`OAuth2AuthorizationServerConfiguration`是一个@Configuration，为OAuth2授权服务器提供最小的默认配置。
`@Import(OAuth2AuthorizationServerConfiguration.class)`，自动注册了一个`AuthorizationServerSettings`, 为授权服务器提供最小的默认配置
`OAuth2AuthorizationServerConfiguration`使用`OAuth2AuthorizationServerConfigurer`来应用默认配置，
并注册了一个由支持OAuth2授权服务器的所有基础设施组件组成的`SecurityFilterChain` @Bean。

### 授权服务进行自定义配置

[Customizing the configuration](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/configuration-model.html#customizing-the-configuration)

```java
public class CustomizingAuthorizationConfig {
	@Bean
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer();
		http.apply(authorizationServerConfigurer);

		authorizationServerConfigurer
				.registeredClientRepository(registeredClientRepository)
				.authorizationService(authorizationService)
				.authorizationConsentService(authorizationConsentService)
				.authorizationServerSettings(authorizationServerSettings)
				.tokenGenerator(tokenGenerator)
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
}
```

- `registeredClientRepository()`: RegisteredClientRepository (REQUIRED) 用于管理新的和现有的客户。
- `authorizationService()`: 用于管理新的和现有的授权的OAuth2AuthorizationService。
- `authorizationConsentService()`: OAuth2AuthorizationConsentService，用于管理新的和现有的授权同意书。
- `authorizationServerSettings()`: 用于定制OAuth2授权服务器的配置设置的AuthorizationServerSettings（必要）。
- `tokenGenerator()`: OAuth2TokenGenerator，用于生成OAuth2授权服务器支持的令牌。
- `clientAuthentication()`: OAuth2客户端认证的配置器。
- `authorizationEndpoint()`: OAuth2授权端点的配置者。
- `tokenEndpoint()`: OAuth2令牌端点的配置者。
- `tokenIntrospectionEndpoint()`: OAuth2 Token Introspection端点的配置器。
- `tokenRevocationEndpoint()`: OAuth2 Token Revocation端点的配置者。
- `authorizationServerMetadataEndpoint()`: OAuth2授权服务器元数据端点的配置者。
- `providerConfigurationEndpoint()`: OpenID Connect 1.0提供者配置端点的配置者。
- `userInfoEndpoint()`: OpenID Connect 1.0 UserInfo端点的配置器。
- `clientRegistrationEndpoint()`: OpenID Connect 1.0客户端注册端点的配置器。

### 配置授权服务器设置

[Configuring Authorization Server Settings](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/configuration-model.html#configuring-authorization-server-settings)

```java
// AuthorizationServerSettings是一个必要的组件。
// AuthorizationServerSettings包含OAuth2授权服务器的配置设置。它指定了协议端点的URI以及发行者标识。协议端点的默认URI如下。源码：
package org.springframework.security.oauth2.server.authorization.settings;

public final class AuthorizationServerSettings extends AbstractSettings {

	//...

	public static Builder builder() {
		return new Builder()
				.authorizationEndpoint("/oauth2/authorize")
				.tokenEndpoint("/oauth2/token")
				.tokenIntrospectionEndpoint("/oauth2/introspect")
				.tokenRevocationEndpoint("/oauth2/revoke")
				.jwkSetEndpoint("/oauth2/jwks")
				.oidcUserInfoEndpoint("/userinfo")
				.oidcClientRegistrationEndpoint("/connect/register");
	}

	//...

}


```

下面的例子展示了如何定制配置设置并注册一个`AuthorizationServerSettings` @Bean。

```java
public class CustomizingAuthorizationConfig {
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
										  .issuer("https://example.com")
										  .authorizationEndpoint("/oauth2/v1/authorize")
										  .tokenEndpoint("/oauth2/v1/token")
										  .tokenIntrospectionEndpoint("/oauth2/v1/introspect")
										  .tokenRevocationEndpoint("/oauth2/v1/revoke")
										  .jwkSetEndpoint("/oauth2/v1/jwks")
										  .oidcUserInfoEndpoint("/connect/v1/userinfo")
										  .oidcClientRegistrationEndpoint("/connect/v1/register")
										  .build();
	}
}

```

`AuthorizationServerContext`是一个持有授权服务器运行环境信息的上下文对象。它提供了对`AuthorizationServerSettings`和
当前发行者标识符（`issuer`）的访问，如果发行人标识符没有在`AuthorizationServerSettings.builder().issuer(String)`
中配置，它将从当前请求中解析
`AuthorizationServerContext`可以通过`AuthorizationServerContextHolder`访问，它通过使用ThreadLocal将其与当前请求线程联系起来

```text
    AuthorizationServerContext serverContext = AuthorizationServerContextHolder.getContext();
	String issuer = serverContext.getIssuer();
```

### 配置客户认证

[Configuring Client Authentication](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/configuration-model.html#configuring-client-authentication)
`OAuth2ClientAuthenticationConfigurer`提供了定制OAuth2客户端认证的能力。它定义了一些扩展点，让你自定义客户端认证请求的预处理、主要处理和后处理逻辑。

`OAuth2ClientAuthenticationConfigurer`提供以下配置选项。

```java
public class AuthorizationClientConfig {
	@Bean
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer();
		http.apply(authorizationServerConfigurer);

		authorizationServerConfigurer
				.clientAuthentication(clientAuthentication ->
											  clientAuthentication
													  .authenticationConverter(authenticationConverter)
													  .authenticationConverters(authenticationConvertersConsumer)
													  .authenticationProvider(authenticationProvider)
													  .authenticationProviders(authenticationProvidersConsumer)
													  .authenticationSuccessHandler(authenticationSuccessHandler)
													  .errorResponseHandler(errorResponseHandler)
				);

		return http.build();
	}
}
```

- `authenticationConverter()`: 添加一个AuthenticationConverter（预处理器），当试图从`HttpServletRequest`
  中提取客户端凭证到`OAuth2ClientAuthenticationToken`的实例时使用
- `authenticationConverters()`: 设置消费者，提供对默认和（可选）添加的`AuthenticationConverter`
  列表的访问，允许添加、删除或定制特定的`AuthenticationConverter`的能力。
- `authenticationProvider()`: 添加一个用于验证`OAuth2ClientAuthenticationToken`的`AuthenticationProvider`（主处理器）。
- `authenticationProviders()`: 设置消费者，提供对默认和（可选）添加的`AuthenticationProvider`
  列表的访问，允许添加、删除或定制特定的`AuthenticationProvider`。
- `authenticationSuccessHandler()`: `AuthenticationSuccessHandler`
  （后处理器），用于处理成功的客户认证，并将`OAuth2ClientAuthenticationToken`与`SecurityContext`相关联。
- `errorResponseHandler()`: `AuthenticationFailureHandler`（后处理器），用于处理客户认证失败并返回`OAuth2Error`响应。

`OAuth2ClientAuthenticationConfigurer`配置`OAuth2ClientAuthenticationFilter`
并将其注册到OAuth2授权服务器`SecurityFilterChain` @Bean。`OAuth2ClientAuthenticationFilter`是处理客户端认证请求的过滤器。

默认情况下，OAuth2令牌端点(Token endpoint)、OAuth2令牌自省端点(Token Introspection endpoint)和OAuth2令牌撤销端点(Token
Revocation endpoint)
都需要客户端认证。支持的客户端认证方法有

- `client_secret_basic`
- `client_secret_post`
- `private_key_jwt`
- `client_secret_jwt`
- `none`（公共客户端）。

`OAuth2ClientAuthenticationFilter`配置的默认值如下:

- `AuthenticationConverter`:一个由`JwtClientAssertionAuthenticationConverter`、`ClientSecretBasicAuthenticationConverter`
  、`ClientSecretPostAuthenticationConverter`和`PublicClientAuthenticationConverter`
  组成的`DelegatingAuthenticationConverter`。
- `AuthenticationManager`:一个由`JwtClientAssertionAuthenticationProvider`、`ClientSecretAuthenticationProvider`
  和`PublicClientAuthenticationProvider`组成的认证管理器。
- `AuthenticationSuccessHandler`:一个内部实现，将 "已认证 "的`OAuth2ClientAuthenticationToken`
  （当前认证）与`SecurityContext`相关联。
- `AuthenticationFailureHandler`:一个内部实现，使用与`OAuth2AuthenticationException`相关的OAuth2Error来返回OAuth2错误响应。

### 自定义Jwt客户端断言验证

[Customizing Jwt Client Assertion Validation](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/configuration-model.html#configuring-client-authentication)
`JwtClientAssertion DecoderFactory.DEFAULT_JWT_VALIDATOR_FACTORY`是默认工厂，为指定的`RegisteredClient`
提供`OAuth2TokenValidator<Jwt>`，用于验证Jwt客户端断言的iss、sub、aud、exp和nbf的claims。

`JwtClientAssertionDecoderFactory`为`setJwtValidatorFactory()`
提供了通过提供`Function<RegisteredClient,`` OAuth2TokenValidator<Jwt>`类型的自定义工厂来覆盖默认Jwt客户端断言验证的能力。

`JwtClientAssertionDecoderFactory`是`JwtClientAssertionAuthenticationProvider`使用的默认`JwtDecoderFactory`
，它为指定的RegisteredClient提供一个JwtDecoder，用于在OAuth2客户端认证过程中认证Jwt Bearer Token。

定制`JwtClientAssertionDecoderFactory`的一个常见用例是验证Jwt客户端断言中的额外要求。

下面的例子显示了如何配置`JwtClientAssertionAuthenticationProvider`与定制的`JwtClientAssertionDecoderFactory`
，以验证Jwt客户端断言中的额外主张。

```java
public class AuthorizationClientConfig {
	@Bean
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer();
		http.apply(authorizationServerConfigurer);

		authorizationServerConfigurer
				.clientAuthentication(clientAuthentication ->
											  clientAuthentication
													  .authenticationProviders(configureJwtClientAssertionValidator())
				);

		return http.build();
	}

	private Consumer<List<AuthenticationProvider>> configureJwtClientAssertionValidator() {
		return (authenticationProviders) ->
				authenticationProviders.forEach((authenticationProvider) -> {
					if (authenticationProvider instanceof JwtClientAssertionAuthenticationProvider) {
						// Customize JwtClientAssertionDecoderFactory
						JwtClientAssertionDecoderFactory jwtDecoderFactory = new JwtClientAssertionDecoderFactory();
						Function<RegisteredClient, OAuth2TokenValidator<Jwt>> jwtValidatorFactory = (registeredClient) ->
								new DelegatingOAuth2TokenValidator<>(
										// Use default validators
										JwtClientAssertionDecoderFactory.DEFAULT_JWT_VALIDATOR_FACTORY.apply(registeredClient),
										// Add custom validator
										new JwtClaimValidator<>("claim", "value"::equals));
						jwtDecoderFactory.setJwtValidatorFactory(jwtValidatorFactory);

						((JwtClientAssertionAuthenticationProvider) authenticationProvider)
								.setJwtDecoderFactory(jwtDecoderFactory);
					}
				});
	}
}
```