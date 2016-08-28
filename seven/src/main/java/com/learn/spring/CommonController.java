package com.learn.spring;

import com.learn.spring.provision.Customer;
import com.learn.spring.repo.CustomerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@EnableWebMvc
public class CommonController {

	@Autowired
	private MongoOperations operations;

	@Autowired
	CustomerRepository repo;

	@RequestMapping(value = "/status", method = RequestMethod.GET)
	public @ResponseBody String getHealthCheck() {
		System.out.println(repo.findByFirstName("Jack"));
		return "ok";
	}

	@RequestMapping(value = "/seed", method = RequestMethod.GET)
	public @ResponseBody String seedData() {
		Customer c = new Customer("Jack", "Bauer");
		c.setRelatives(Arrays.asList("A", "B", "Z"));
		Map<String, List<String>> mp = new HashMap<String, List<String>>();
		mp.put("1", Arrays.asList("1a", "1b"));
		mp.put("2", Arrays.asList("2a", "2c"));
		mp.put("3", Arrays.asList("3x", "3z"));
		c.setComplex(mp);
		operations.save( c );
		return "ok";
	}

	@RequestMapping(value = "/read", method = RequestMethod.GET)
	public @ResponseBody Customer readData() {
		Query searchUserQuery = new Query(Criteria.where("firstName").is("Jack"));
		Customer savedUser = operations.findOne(searchUserQuery, Customer.class);
		return savedUser;
	}

}
