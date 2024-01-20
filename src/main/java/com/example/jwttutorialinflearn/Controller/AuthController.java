package com.example.jwttutorialinflearn.Controller;

import com.example.jwttutorialinflearn.Dto.LoginDto;
import com.example.jwttutorialinflearn.Dto.TokenDto;
import com.example.jwttutorialinflearn.Jwt.JwtFilter;
import com.example.jwttutorialinflearn.Jwt.TokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    //로그인
    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {
        //LoginDto로 들어오는 입력을 받아서 권한토큰을 생성한다.
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        //권한토큰을 이용하여 Authentication 객체를 생성.
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        //SecurityContext에 저장.
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //Authentication 객체를 이용하여 JWT 토큰을 생성.
        String jwt = tokenProvider.createToken(authentication);

        //JWT 토큰을 Response Header에 넣어주고,
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        //TokenDto를 이용해서 Response Body에도 넣어줘서 return 한다.
        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}