package jdbc.auth.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jdbc.auth.security.filter.JwtAuthFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// RoleHierarchy implementation allows ADMIN to access any resource available
	// for admin, user, and guest roles,
	// where as user to access any resource available for user and guest roles.
	@Bean
	public RoleHierarchy roleHierarchy() {
		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl.setHierarchy("ROLE_ADMIN > ROLE_USER > ROLE_GUEST");
		return roleHierarchyImpl;
	}

	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private JwtAuthFilter jwtAuthFilter;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().authorizeRequests().antMatchers("/login", "/register", "/signup", "/authenticate")
				.permitAll().antMatchers("/admin/**").hasRole("ADMIN").antMatchers("/users/**").hasRole("USER").
//						antMatchers("/users/**").access("@webSecurityCustomChecks.check(authentication,request)").
//						antMatchers("/users/**").access("hasRole('ADMIN') and hasRole('USER')").
				antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')").anyRequest().denyAll().and()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

	}

}
