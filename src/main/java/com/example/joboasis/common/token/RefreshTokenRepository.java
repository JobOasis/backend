package com.example.joboasis.common.token;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Boolean existsByToken(String token);
    void deleteByToken(String token);
}
