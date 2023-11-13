package com.srikanth.security.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.srikanth.security.demo.domain.User;

//public interface UserRepository extends JpaRepository<User, Integer> {
    
//	// Returns that one user name that matches with String 'username'
//    User findByUsername(String username);

// Ensures 1 query for the queried username and its associated authorities list:
// Avoids the N+1 select problem
public interface UserRepository extends JpaRepository<User, Integer> {
    @Query("SELECT u FROM User u JOIN FETCH u.authorities WHERE u.username = :username")
    User findByUsername(@Param("username") String username);
}

//
//CREATE TABLE users (
//	    id INT AUTO_INCREMENT PRIMARY KEY,
//	    username VARCHAR(50) UNIQUE NOT NULL,
//	    password VARCHAR(100) NOT NULL
//	);
//
//	CREATE TABLE authorities (
//	    id INT AUTO_INCREMENT PRIMARY KEY,
//	    name VARCHAR(50) NOT NULL
//	);
//
//	CREATE TABLE user_authorities (
//	    user_id INT NOT NULL,
//	    authority_id INT NOT NULL,
//	    PRIMARY KEY (user_id, authority_id),
//	    FOREIGN KEY (user_id) REFERENCES users(id),
//	    FOREIGN KEY (authority_id) REFERENCES authorities(id)
//	);
