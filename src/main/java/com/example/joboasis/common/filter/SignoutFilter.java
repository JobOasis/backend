package com.example.joboasis.common.filter;

import com.example.joboasis.common.token.RefreshTokenService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

import static com.example.joboasis.common.token.RefreshTokenService.getRefreshToken;

@RequiredArgsConstructor
public class SignoutFilter extends GenericFilterBean {

    private final JWTVerifier jwtVerifier;
    private final RefreshTokenService refreshTokenService;
    private static final RequestMatcher signoutRequestMatcher = new OrRequestMatcher(new AntPathRequestMatcher("/signout", "POST"),
            new AntPathRequestMatcher("/company/signout", "POST"));

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String refreshToken;
        //signoutRequestMatcher 와 일치하지 않으면 SignoutFilter 통과
        if (!signoutRequestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            refreshToken = getRefreshToken(request.getCookies());
            jwtVerifier.verifyRefreshToken(refreshToken);
            if (!refreshTokenService.existsByRefreshToken(refreshToken)) throw new JwtException("Invalid Refresh Token");

        } catch (RuntimeException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //로그아웃 진행
        //Refresh 토큰 DB에서 제거
        refreshTokenService.deleteByRefreshToken(refreshToken);

        Cookie cookie = setEmptyCookie();

        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);
    }

    private static Cookie setEmptyCookie() {
        Cookie cookie = new Cookie("joboasis_refresh", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        return cookie;
    }

}
