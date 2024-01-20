package com.example.jwttutorialinflearn.Jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean {
    //

    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);
    private static final String AUTHORITIES_KEY = "auth";
    private final String secret;
    private final long tokenValidityInMilliseconds;
    private Key key;

    //의존성 주입
    public TokenProvider(
            //yml 파일에서 설정했던 secret 값과, 유효기간.
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
        this.secret = secret;
        this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
    }

    //주입받은 secret값을 Base64 Decode해서 key변수에 할당
    @Override
    public void afterPropertiesSet() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    //Authentication 객체의 권한정보를 이용해서 토큰을 생성하는 createToken 메소드
    public String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()//권한들 가져옴.
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date validity = new Date(now + this.tokenValidityInMilliseconds); //yml에서 설정했던 토큰 만료시간

        //JWT 토큰 생성 후 리턴
        return Jwts.builder()
                .setSubject(authentication.getName())//아이디
                .claim(AUTHORITIES_KEY, authorities)//권한들
                .signWith(key, SignatureAlgorithm.HS512)//알고리즘
                .setExpiration(validity)//유효기간
                .compact();
    }

    //토큰을 파라미터로 받아서 토큰에 담긴 정보를 이용해 Authentication 객체를 리턴하는 메소드
    public Authentication getAuthentication(String token) {
        //파리미터로 받은 토큰으로 클레임을 만든다.
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))//클레임에서 권한정보를 빼낸다.
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        //권한정보를 이용해 User 객체를 만든다.
        User principal = new User(claims.getSubject(), "", authorities);
        //User객체, 토큰, 권한정보를 이용해 최종적으로 Authentication 객체를 리턴한다.
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    //토큰을 파라미터로 받아서 토큰의 유효성 검증을 수행하는 메소드
    public boolean validateToken(String token) {
        try {
            //받은 토큰으로 파싱을 해보고 발생하는 예외들을 잡는다.
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            //정상이면 true 문제가 있으면 false
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            logger.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            logger.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            logger.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            logger.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }
}