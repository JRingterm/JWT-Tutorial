package com.example.jwttutorialinflearn.Config;

import com.example.jwttutorialinflearn.Jwt.JwtAccessDeniedHandler;
import com.example.jwttutorialinflearn.Jwt.JwtAuthenticationEntryPoint;
import com.example.jwttutorialinflearn.Jwt.JwtSecurityConfig;
import com.example.jwttutorialinflearn.Jwt.TokenProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    //생성자 주입. 만들었던 JWT관련 클래스를 주입해준다.
    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    //PasswordEncoder로는 BCryptPasswordEncoder를 사용한다.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) //token을 쓰는 방식이므로 csrf를 disable

                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .accessDeniedHandler(jwtAccessDeniedHandler) //필요한 권한이 존재하지 않는 경우
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint) //유효한 자격증명을 제공하지 않고 접근하려할 경우
                )

                //HttpServletRequest를 사용하는 요청들에 대한 접근제한을 설정하겠다.
                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                        //(로그인API, 회원가입API)는 토큰이 없는 상태에서 요청이 들어오므로 모두 허용.
                        .requestMatchers("/api/hello", "/api/authenticate", "/api/signup").permitAll()
                        .requestMatchers(PathRequest.toH2Console()).permitAll()
                        .anyRequest().authenticated() //나머지 요청들에 대해서는 인증을 받야아 한다.
                )

                // 세션을 사용하지 않기 때문에 세션 설정을 STATELESS로 설정
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // enable h2-console
                .headers(headers ->
                        headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                )

                //JwtFilter를 addFilterBefore로 등록했던 JwtSecurityConfig 클래스도 적용해줌.
                .with(new JwtSecurityConfig(tokenProvider), customizer -> {});
        return http.build();
    }
}