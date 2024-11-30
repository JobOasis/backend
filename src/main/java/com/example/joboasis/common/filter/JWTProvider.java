package com.example.joboasis.common.filter;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTProvider {

    private SecretKey secretKey;
    private static final int ACCESS_EXP = 10 * 60 * 1000;  //10분
    private static final long REFRESH_EXP = 30L * 24 * 60 * 60 * 1000;  //30일

    public JWTProvider(@Value("${spring.jwt.secret}") String secret) {
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String createAccessToken(String email, String authority) {
        return Jwts.builder()
//                .issuer("잡오아시스 서버 주소")
                .claim("email", email)
                .claim("token_type", "access")
                .claim("authority", authority)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + ACCESS_EXP))
                .signWith(secretKey)
                .compact();
    }

    public String createRefreshToken(String email, String authority) {
        return Jwts.builder()
//                .issuer("잡오아시스 서버 주소")
                .claim("email", email)
                .claim("token_type", "refresh")
                .claim("authority", authority)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + REFRESH_EXP))
                .signWith(secretKey)
                .compact();
    }

}