package com.example.joboasis.common.token;

import jakarta.servlet.http.Cookie;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private static final int REFRESH_EXP = 30 * 24 * 60 * 60;  //30일
    private static final String REFRESH_COOKIE_NAME = "joboasis_refresh";

    @Transactional
    public void addRefreshToken(RefreshToken refreshToken) {
        refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public void deleteByRefreshToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }

    @Transactional(readOnly = true)
    public boolean existsByRefreshToken(String token) {
        return refreshTokenRepository.existsByToken(token);
    }

    public static String getRefreshToken(Cookie[] cookies) {
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(REFRESH_COOKIE_NAME)) {
                return cookie.getValue();
            }
        }
        throw new RuntimeException("Refresh Token Not Exists in Cookie");
    }

    public static String setRefreshTokenCookie(String value) {
        return REFRESH_COOKIE_NAME + "=" + value + "; Max-Age=" + REFRESH_EXP + "; HttpOnly" + "; Secure" + "; Path=/";
    }

}
