package com.example.demo.auth;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.example.demo.security.ApplicationUserRole;
import com.google.common.collect.Lists;


@Repository("fake")
public class ApplicationUserDaoService implements ApplicationUserDao {
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public ApplicationUserDaoService(PasswordEncoder passwordEncoder) {
		
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectUserByUsername(String username) {
		// TODO Auto-generated method stub
		return getApplicationUsers()
				.stream()
				.filter(user->username.equals(user.getUsername()))
				.findFirst();
				
	}
	
	private List<ApplicationUser> getApplicationUsers() {
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
				new ApplicationUser(ApplicationUserRole.STUDENT.getGrantedAuthorities(), 
						passwordEncoder.encode("123"),
						"milo",
						true,
						true,
						true,
						true),
				
				new ApplicationUser(ApplicationUserRole.ADMIN.getGrantedAuthorities(), 
						passwordEncoder.encode("123"),
						"admin",
						true,
						true,
						true,
						true),
				
				
				new ApplicationUser(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(), 
						passwordEncoder.encode("123"),
						"trainnie",
						true,
						true,
						true,
						true)
				
				);
		return applicationUsers;
	}

}
