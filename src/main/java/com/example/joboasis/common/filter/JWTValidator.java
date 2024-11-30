package com.example.joboasis.common.filter;

import com.example.joboasis.domain.member.entity.Member;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

@RequiredArgsConstructor
public class JWTValidator extends OncePerRequestFilter {

    private final JWTVerifier jwtVerifier;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        Claims payload;

        if (!isBearerTokenType(authorization)) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = getAccessToken(authorization);

        try {
            payload = jwtVerifier.verifyAccessToken(accessToken);

        } catch (ExpiredJwtException e) {
            PrintWriter writer = response.getWriter();
            writer.print("Access Token Expired");

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;  //프론트에서 /reissue 로 redirect
        } catch (JwtException e) {
            PrintWriter writer = response.getWriter();
            writer.print(e);

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String email = jwtVerifier.getEmail(payload);
        String authority = jwtVerifier.getAuthority(payload);

        Member member = new Member(email, authority);

        //UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(member);

        //스프링 시큐리티 인증 토큰 생성
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(customUserDetails, null, customUserDetails.getAuthorities());
        //쓰레드 로컬에 사용자 등록
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);

        filterChain.doFilter(request, response);
    }

    private static String getAccessToken(String authorization) {
        return authorization.split(" ")[1];
    }

    private static boolean isBearerTokenType(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer")) {
            return false;
        }
        return true;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {  //reissue는 JWTFilter를 거치지 않게 처리
        return request.getRequestURI().equals("/reissue");
    }
}