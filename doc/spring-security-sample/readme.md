# Spring security sample

## 相关文章博客

[Spring Security 源码解读 ：基本架构及初始化](https://blog.csdn.net/weixin_41866717/article/details/128848734)

[深入理解 FilterChainProxy【源码篇】](https://wangsong.blog.csdn.net/article/details/107456398)

[深入理解 SecurityConfigurer 【源码篇】](https://wangsong.blog.csdn.net/article/details/107480688)

[深入理解 HttpSecurity【源码篇】](https://wangsong.blog.csdn.net/article/details/107509727)

[深入理解 WebSecurityConfigurerAdapter【源码篇】](https://wangsong.blog.csdn.net/article/details/107655180)

## 理解spring security中的原理

### spring-security的请求拦截早于DispatcherServlet

在spring-security中，请求一般会先经过SecurityFilterProxy的处理后，才会来到DispatcherServlet进行请求的servlet映射

### spring-security默认的`/login`接口

- /login GET

  这个接口用于请求登录页面，生成页面的逻辑在DefaultLoginPageConfigurer中，生成页面后，会立即响应请求！
- /login POST

  这个请求用于spring-security的表单登录，最终被UsernamePasswordAuthenticationFilter进行拦截处理.

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