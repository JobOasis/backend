package com.example.joboasis.common.token;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Date;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {

    private static final long REFRESH_EXP = 30L * 24 * 60 * 60 * 1000;  //30일

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String email;
    private String token;
    private Date expireDate;

    public RefreshToken(String email, String token) {
        this.email = email;
        this.token = token;
        this.expireDate = new Date(System.currentTimeMillis() + REFRESH_EXP);
    }
}
