package com.example.joboasis.common.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Component
public class JWTVerifier {

    private SecretKey secretKey;

    public JWTVerifier(@Value("${spring.jwt.secret}") String secret) {
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public Claims verifyAccessToken(String token) {
        Claims payload = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
        String tokenType = getTokenType(payload);
        if (!tokenType.equals("access")) throw new JwtException("Invalid Access Token");

        return payload;
    }

    public Claims verifyRefreshToken(String token) {
        Claims payload = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
        String tokenType = getTokenType(payload);
        if (!tokenType.equals("refresh")) throw new JwtException("Invalid Refresh Token");

        return payload;
    }

    private String getTokenType(Claims payload) {
        return payload.get("token_type", String.class);
    }

    public String getEmail(Claims payload) {
        return payload.get("email", String.class);
    }

    public String getAuthority(Claims payload) {
        return payload.get("authority", String.class);
    }
}
