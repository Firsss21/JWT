package firsov.study.Spring.JWT;

import firsov.study.Spring.JWT.domain.Role;
import firsov.study.Spring.JWT.domain.User;
import firsov.study.Spring.JWT.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringJwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.clearUsers();
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_SUPERADMIN"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));

			userService.saveUser(new User(null, "John Travolta","john", "12345", new ArrayList<>()));
			userService.saveUser(new User(null, "Will Smith","will", "12345", new ArrayList<>()));
			userService.saveUser(new User(null, "Jim Carry","jim", "12345", new ArrayList<>()));
			userService.saveUser(new User(null, "Arnold Schwarzenegger","arnold", "12345", new ArrayList<>()));

			userService.addRoleToUser("john", "ROLE_USER");
			userService.addRoleToUser("john", "ROLE_ADMIN");
			userService.addRoleToUser("will", "ROLE_USER");
			userService.addRoleToUser("will", "ROLE_MANAGER");
			userService.addRoleToUser("jim", "ROLE_USER");
			userService.addRoleToUser("arnold", "ROLE_USER");
			userService.addRoleToUser("arnold", "ROLE_ADMIN");
			userService.addRoleToUser("arnold", "ROLE_SUPERADMIN");


		};
	}
}
