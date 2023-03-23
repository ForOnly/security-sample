package com.foronly.sample.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
				.antMatchers("/admin/**").hasRole("ADMIN")
				.anyRequest().authenticated()
				.and()
				.formLogin()
				.permitAll()
				.and()
				.logout()
				.permitAll();
		return http.build();
	}

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
}
