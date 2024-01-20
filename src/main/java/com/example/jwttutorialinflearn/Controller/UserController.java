package com.example.jwttutorialinflearn.Controller;

import com.example.jwttutorialinflearn.Dto.UserDto;
import com.example.jwttutorialinflearn.Service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.io.IOException;

@RestController
@RequestMapping("/api")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    //회원가입
    @PostMapping("/signup")
    public ResponseEntity<UserDto> signup(
            @Valid @RequestBody UserDto userDto
    ) {
        //UserDto로 받아서 UserService의 signup 메소드 호출
        return ResponseEntity.ok(userService.signup(userDto));
    }

    //===============username을 기준으로 유저 정보와 권한 정보를 리턴하는 API=======================

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER','ADMIN')") //USER, ADMIN 두가지 권한 모두 호출할 수 있는 API
    public ResponseEntity<UserDto> getMyUserInfo(HttpServletRequest request) {
        return ResponseEntity.ok(userService.getMyUserWithAuthorities());
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasAnyRole('ADMIN')") //ADMIN 권한만 호출할 수 있는 API
    public ResponseEntity<UserDto> getUserInfo(@PathVariable("username") String username) {
        return ResponseEntity.ok(userService.getUserWithAuthorities(username));
    }
}