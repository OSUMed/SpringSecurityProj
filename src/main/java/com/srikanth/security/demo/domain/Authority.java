package com.srikanth.security.demo.domain;

import org.springframework.security.core.GrantedAuthority;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;


@Entity
public class Authority implements GrantedAuthority {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

	private String name; // e.g., "ROLE_USER", "ROLE_ADMIN"

	@Override
	public String getAuthority() {
		return name;
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
}

//
//INSERT INTO authorities (name) VALUES ('ROLE_USER');
//INSERT INTO authorities (name) VALUES ('ROLE_ADMIN');
