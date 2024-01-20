package com.example.jwttutorialinflearn.Jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

public class JwtFilter extends GenericFilterBean {
    //GenericFilterBean을 extends

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);
    public static final String AUTHORIZATION_HEADER = "Authorization";
    private TokenProvider tokenProvider;

    //JwtFilter는 TokenProvider를 주입받는다.
    public JwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }


    //JWT 토큰의 인증 정보를 현재 실행중인 SecurityContext에 저장하는 메소드
    //실제 필터링 로직을 작성하는 메소드이다.
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        //resolveToken으로 토큰을 받아온다.
        String jwt = resolveToken(httpServletRequest);
        String requestURI = httpServletRequest.getRequestURI(); //요청한 API URL

        //이 토큰의 유효성 검증을 한다.
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            //토큰이 정상적이면 토큰에서 Authentication 객체를 받아와서 SecurityContext에 저장해줌.
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
        } else {
            logger.debug("유효한 JWT 토큰이 없습니다, uri: {}", requestURI);
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    //필터링을 하기 위해서 토큰 정보가 필요.
    //Request Header에서 토큰 정보를 꺼내오기 위한 메소드
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            //Bearer "토큰sfeosfjso" 식이기 때문에, 토큰은 7번째 인덱스부터 시작.
            return bearerToken.substring(7);
        }

        return null;
    }
}