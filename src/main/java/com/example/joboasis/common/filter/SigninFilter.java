package com.example.joboasis.common.filter;

import com.example.joboasis.common.token.RefreshToken;
import com.example.joboasis.common.token.RefreshTokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import static com.example.joboasis.common.token.RefreshTokenService.setRefreshTokenCookie;

public class SigninFilter extends AbstractAuthenticationProcessingFilter {

    private final JWTProvider jwtProvider;
    private final ObjectMapper objectMapper;
    private final RefreshTokenService refreshTokenService;

    public SigninFilter(JWTProvider jwtProvider, ObjectMapper objectMapper, AuthenticationManager authenticationManager, RefreshTokenService refreshTokenService) {
        super(new OrRequestMatcher(new AntPathRequestMatcher("/signin", "POST"),
                new AntPathRequestMatcher("/company/signin", "POST")), authenticationManager);
        this.jwtProvider = jwtProvider;
        this.objectMapper = objectMapper;
        this.refreshTokenService = refreshTokenService;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        checkHttpMethod(request);

        Map<String, String> emailPasswordMap = getEmailAndPassword(request);
        String email = emailPasswordMap.get("email");
        String password = emailPasswordMap.get("password");

        Authentication authentication = UsernamePasswordAuthenticationToken.unauthenticated(email, password);

        return this.getAuthenticationManager().authenticate(authentication);
    }


    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
        String email = authentication.getName();
        String authority = getAuthority(authentication);

        //토큰 생성
        String accessToken = jwtProvider.createAccessToken(email, authority);
        String refreshToken = jwtProvider.createRefreshToken(email, authority);

        //Refresh 토큰 DB에 저장
        refreshTokenService.addRefreshToken(new RefreshToken(email, refreshToken));

        //응답 설정
        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        response.setHeader(HttpHeaders.SET_COOKIE, setRefreshTokenCookie(refreshToken));
        response.setStatus(HttpStatus.OK.value());
    }


    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }


    private void checkHttpMethod(HttpServletRequest request) {
        //Http Method 에러 핸들링
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication Method Not Supported: " + request.getMethod());
        }
    }


    private Map<String, String> getEmailAndPassword(HttpServletRequest request) throws IOException {
        ServletInputStream inputStream = request.getInputStream();
        String messageBody = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);

        return objectMapper.readValue(messageBody, Map.class);
    }


    private String getAuthority(Authentication authentication) {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority grantedAuthority = iterator.next();
        return grantedAuthority.getAuthority();
    }
}
