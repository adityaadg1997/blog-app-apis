package com.codewithaditya.blog;

import com.codewithaditya.blog.config.AppConstants;
import com.codewithaditya.blog.entitiles.Role;
import com.codewithaditya.blog.repositories.RoleRepo;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@SpringBootApplication
public class BlogAppApisApplication implements CommandLineRunner{

	@Autowired
	private RoleRepo roleRepo;

	@Autowired
	private PasswordEncoder passwordEncoder;

	public static void main(String[] args) {
		SpringApplication.run(BlogAppApisApplication.class, args);
	}

	@Bean
	public ModelMapper modelMapper(){
		return new ModelMapper();
	}


	@Override
	public void run(String... args) throws Exception {
		System.out.println(this.passwordEncoder.encode("xyz"));

		try {

			Role roleAdmin = new Role();
			roleAdmin.setId(AppConstants.ADMIN_USER);
			roleAdmin.setName(AppConstants.ADMIN_USER_ROLE);

			Role roleNormal = new Role();
			roleNormal.setId(AppConstants.NORMAL_USER);
			roleNormal.setName(AppConstants.NORMAL_USER_ROLE);

			//adding into list of role
			List<Role> roles = List.of(roleAdmin, roleNormal);

			List<Role> savedRoles = this.roleRepo.saveAll(roles);

			savedRoles.forEach(role -> System.out.println(role.getName()));

		}catch (Exception e){
			e.printStackTrace();
		}
	}
}
