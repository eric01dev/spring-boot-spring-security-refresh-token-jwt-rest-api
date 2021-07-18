package com.example.springbootspringsecurityrefreshtokenjwtrestapi.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.springbootspringsecurityrefreshtokenjwtrestapi.models.ERole;
import com.example.springbootspringsecurityrefreshtokenjwtrestapi.models.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
	
	Optional<Role> findByRolename(ERole rolename);
}
