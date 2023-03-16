package com.foronly.sample.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * <p>
 *
 * </p>
 *
 * @author li_cang_long
 * @since 2023/3/15 1:36
 */
@Configuration
public class SecurityConfiguration {
	// @Bean
	// public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	// 	http
	// 			.authorizeRequests()
	// 			.antMatchers("/admin/**").hasRole("ADMIN")
	// 			.anyRequest().authenticated()
	// 			.and()
	// 			.formLogin()
	// 			.permitAll()
	// 			.and()
	// 			.logout()
	// 			.permitAll();
	// 	return http.build();
	// }

	@Bean
	public InMemoryUserDetailsManager userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder()
							   .username("user")
							   .password("password")
							   .roles("USER")
							   .build();
		UserDetails admin = User.withDefaultPasswordEncoder()
								.username("admin")
								.password("password")
								.roles("ADMIN")
								.build();
		return new InMemoryUserDetailsManager(user, admin);
	}


	/*
	 全局的配置 通过注入AuthenticationManagerBuilder实现
	 @Autowired
	 public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
	 	auth.inMemoryAuthentication()
	 		.withUser("user").password("{noop}password").roles("USER")
	 		.and()
	 		.withUser("admin").password("{noop}password").roles("ADMIN");
	 }
	*/
}
