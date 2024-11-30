package com.example.joboasis.common.token;

import com.example.joboasis.common.filter.JWTProvider;
import com.example.joboasis.common.filter.JWTVerifier;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import static com.example.joboasis.common.token.RefreshTokenService.setRefreshTokenCookie;

@RestController
@RequiredArgsConstructor
public class RefreshTokenController {

    private final JWTVerifier jwtVerifier;
    private final JWTProvider jwtProvider;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissueTokens(@CookieValue("joboasis_refresh") String refreshToken) {
        Claims payload;

        try {
            payload = jwtVerifier.verifyRefreshToken(refreshToken);
            if (!refreshTokenService.existsByRefreshToken(refreshToken)) throw new JwtException("Invalid Refresh Token");

        } catch (ExpiredJwtException e) {
            return new ResponseEntity<>("Refresh Token Expired", HttpStatus.BAD_REQUEST);
            //로그아웃
        } catch (RuntimeException e) {
            return new ResponseEntity<>(e, HttpStatus.BAD_REQUEST);
        }

        String email = jwtVerifier.getEmail(payload);
        String authority = jwtVerifier.getAuthority(payload);

        //make new JWT
        String newAccessToken = jwtProvider.createAccessToken(email, authority);
        String newRefreshToken = jwtProvider.createRefreshToken(email, authority);

        //Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
        refreshTokenService.deleteByRefreshToken(refreshToken);
        refreshTokenService.addRefreshToken(new RefreshToken(email, newRefreshToken));

        //response
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setBearerAuth(newAccessToken);
        httpHeaders.add(HttpHeaders.SET_COOKIE, setRefreshTokenCookie(newRefreshToken));

        return new ResponseEntity<>(httpHeaders, HttpStatus.OK);
    }

}
