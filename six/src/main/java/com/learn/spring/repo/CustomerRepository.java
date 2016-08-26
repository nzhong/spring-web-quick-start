package com.learn.spring.repo;

import com.learn.spring.provision.Customer;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CustomerRepository extends MongoRepository<Customer, String> {

	public Customer findByFirstName(String firstName);
	public List<Customer> findByLastName(String lastName);

}