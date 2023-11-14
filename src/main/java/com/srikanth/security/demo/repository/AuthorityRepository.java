package com.srikanth.security.demo.repository;

import com.srikanth.security.demo.domain.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorityRepository extends JpaRepository<Authority, Integer> {
    Authority findByName(String name);
}
