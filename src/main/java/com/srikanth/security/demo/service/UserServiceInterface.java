package com.srikanth.security.demo.service;

import java.util.Optional;
import com.srikanth.security.demo.domain.User;

public interface UserServiceInterface {
    Optional<User> findById(Integer userId);
    // Define other methods if needed
}
