package com.srikanth.security.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.srikanth.security.demo.domain.Authority;

public interface AuthorityRepository extends JpaRepository<Authority, Integer> {
	Authority findByName(String name);
}