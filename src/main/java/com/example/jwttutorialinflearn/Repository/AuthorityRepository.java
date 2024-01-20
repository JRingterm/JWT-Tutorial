package com.example.jwttutorialinflearn.Repository;

import com.example.jwttutorialinflearn.Entity.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorityRepository extends JpaRepository<Authority, String> {
}
