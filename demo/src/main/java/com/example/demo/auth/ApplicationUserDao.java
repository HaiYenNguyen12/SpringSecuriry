package com.example.demo.auth;

import java.util.Optional;

public interface ApplicationUserDao {
	
	public Optional<ApplicationUser> selectUserByUsername(String username);

}
