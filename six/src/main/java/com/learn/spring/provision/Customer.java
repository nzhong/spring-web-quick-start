package com.learn.spring.provision;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;
import java.util.Map;

@Document(collection = "customer")
public class Customer {

	@Id
	private String id;
	private String firstName;
	private String lastName;
	private List<String> relatives;
	private Map<String,List<String>> complex;

	public Customer() {
		super();
	}

	public Customer(String firstName, String lastName) {
		super();
		this.firstName = firstName;
		this.lastName = lastName;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public List<String> getRelatives() {
		return relatives;
	}

	public Map<String, List<String>> getComplex() {
		return complex;
	}

	public void setComplex(Map<String, List<String>> complex) {
		this.complex = complex;
	}

	public void setRelatives(List<String> relatives) {
		this.relatives = relatives;
	}

	@Override
	public String toString() {
		return "Customer [id=" + id + ", firstName=" + firstName
				+ ", lastName=" + lastName + ", relatives=" + relatives +", complex=" +complex +"]";
	}
}