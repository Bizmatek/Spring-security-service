package com.security.service;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.security.service.dao.UserRepository;

@SpringBootApplication
public class Oauth2serviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(Oauth2serviceApplication.class, args);
	}

    @Bean
    ApplicationRunner dataLoader(UserRepository repository, PasswordEncoder encoder) {
		return args -> {
			repository.save(new Users("habuma", encoder.encode("password"), "ROLE_ADMIN"));
			repository.save(new Users("tacochef", encoder.encode("password"), "ROLE_ADMIN"));
			};
	}
}
