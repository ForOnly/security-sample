# Spring security sample

## 理解spring security中的原理

### 默认过滤器链和默认使用的过滤器

在spring security中，存在一条默认的过滤器链，当开发者未自定义过滤器链时，spring security会启用这条默认的过滤器链，
spring security中，存在一些默认使用的过滤器，在开发者自定义过滤器链时，这些过滤器会被自动加入到过滤器链中！

## 定制化spring-security

[弃用WebSecurityConfigurerAdapter](https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter)

### 自定义UserDetailsService

- jdbc身份认证

```java

@Configuration
public class SecurityConfiguration {

	@Bean
	public DataSource dataSource() {
		// 需要使用到数据源，此处使用嵌入式数据库H2
		return new EmbeddedDatabaseBuilder()
				.setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
				.build();
	}

	@Bean
	public UserDetailsManager users(DataSource dataSource) {
		UserDetails user = User.withDefaultPasswordEncoder()
							   .username("user")
							   .password("password")
							   .roles("USER")
							   .build();
		JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
		users.createUser(user);
		return users;
	}
}
```

- 基于内存的身份认证

```java

@Configuration
public class SecurityConfiguration {
	@Bean
	public InMemoryUserDetailsManager userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder()
							   .username("user")
							   .password("password")
							   .roles("USER")
							   .build();
		return new InMemoryUserDetailsManager(user);
	}
}
```

### 配置WebSecurity

推荐的做法是注册一个WebSecurityCustomizer 实例bean：

```java

@Configuration
public class SecurityConfiguration {

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().antMatchers("/ignore1", "/ignore2");
	}

}
```