package com.learn.spring.repo;

import com.learn.spring.provision.AppUser;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AppUserRepository extends MongoRepository<AppUser, String> {

	public List<AppUser> getByUsername(String username);

}