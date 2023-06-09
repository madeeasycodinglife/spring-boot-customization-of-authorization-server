package com.madeeasy.repositoty;

import com.madeeasy.entity.SecurityUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<SecurityUser, Integer> {

    SecurityUser findByUsername(String username);
}
