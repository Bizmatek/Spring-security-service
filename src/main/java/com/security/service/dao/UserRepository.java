package com.security.service.dao;

import org.springframework.data.repository.CrudRepository;

import com.security.service.Users;



public interface UserRepository extends CrudRepository<Users, Long>{
	Users findByUsername(String username);
}
