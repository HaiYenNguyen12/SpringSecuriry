package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.example.demo.auth.ApplicationUserService;

import static com.example.demo.security.ApplicationUserRole.*;

import java.util.concurrent.TimeUnit;

@SuppressWarnings("deprecation")
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
	
	
	private final PasswordEncoder passwordEncoder ;
	private final ApplicationUserService appoApplicationUserService;
	@Autowired
	public  ApplicationSecurityConfig(PasswordEncoder passwordEncoder,ApplicationUserService applicationUserService ) {
		this.passwordEncoder = passwordEncoder;
		this.appoApplicationUserService = applicationUserService;
	}
		
	
		
		
	
	@Override
	protected void configure (HttpSecurity http) throws Exception {
		
		http
		.csrf().disable()
		.authorizeHttpRequests()
		.antMatchers("/","index","/css/*","/js/*")
		.permitAll()
		.antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
//		.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//		.antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//		.antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//		.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
		.anyRequest()
		.authenticated()
		.and()
//		.httpBasic();
		.formLogin()
		.loginPage("/login").permitAll()
		.defaultSuccessUrl("/course", true)
		.passwordParameter("pass")
		.usernameParameter("name")
		.and()
		.rememberMe().tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
		.key("somthingsocute")
		.rememberMeParameter("remember")
		
		.and()
		.logout()
		.logoutUrl("/logout")
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
		.clearAuthentication(true)
		.invalidateHttpSession(true)
		.deleteCookies("JSESSIONID","remember-me")
		.logoutSuccessUrl("/login");
	}
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenicationProvider());
	}
	@Bean
	public DaoAuthenticationProvider daoAuthenicationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(appoApplicationUserService);
		return provider;
//		@Override
//		@Bean
//		protected UserDetailsService userDetailsService() {
//			UserDetails milo = User.builder()
//					.username("milo")
//					.password(passwordEncoder.encode("123"))
////					.roles(STUDENT.name())
//					.authorities(STUDENT.getGrantedAuthorities())
//					.build();
//			
//			
//			UserDetails admin = User.builder()
//					.username("admin")
//					.password(passwordEncoder.encode("123"))
////					.roles(ADMIN.name())
//					.authorities(ADMIN.getGrantedAuthorities())
//					.build();
//			
//			UserDetails trainnie_admin = User.builder()
//					.username("trainnie")
//					.password(passwordEncoder.encode("123"))
////					.roles(ADMINTRAINEE.name())
//					.authorities(ADMINTRAINEE.getGrantedAuthorities())
//					.build();
			
//			return new InMemoryUserDetailsManager(milo, admin, trainnie_admin);
					
		}
		
	
}
