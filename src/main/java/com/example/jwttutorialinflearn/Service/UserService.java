package com.example.jwttutorialinflearn.Service;

import java.util.Collections;

import com.example.jwttutorialinflearn.Dto.UserDto;
import com.example.jwttutorialinflearn.Entity.Authority;
import com.example.jwttutorialinflearn.Entity.User;
import com.example.jwttutorialinflearn.Exception.DuplicateMemberException;
import com.example.jwttutorialinflearn.Exception.NotFoundMemberException;
import com.example.jwttutorialinflearn.Repository.UserRepository;
import com.example.jwttutorialinflearn.Util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    //회원가입
    @Transactional
    public UserDto signup(UserDto userDto) {
        //UserDto로 받은 데이터중 username을 기준으로 하여 DB에 이미 있는지 확인.
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new DuplicateMemberException("이미 가입되어 있는 유저입니다.");
        }
        //username이 중복이 없다면 권한정보를 생성
        Authority authority = Authority.builder()
                .authorityName("ROLE_USER") //ROLE_USER라는 권한을 가짐.
                .build();
        //받아온 UserDto의 정보와 생성한 권한정보를 이용하여 Entity.User 객체 생성
        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();
        //DB에 저장.
        return UserDto.from(userRepository.save(user));
    }
    //유저, 권한정보를 가져오는 메소드 2개. 허용권한이 다르므로 권한검증에 대한 테스트로 사용할 것이다.

    //username으로 유저 객체, 권한정보를 가져오는 메소드
    @Transactional(readOnly = true)
    public UserDto getUserWithAuthorities(String username) {
        return UserDto.from(userRepository.findOneWithAuthoritiesByUsername(username).orElse(null));
    }

    //현재 SecurityContext에 저장된 username에 해당하는 유저 객체와 권한정보를 가져오는 메소드
    @Transactional(readOnly = true)
    public UserDto getMyUserWithAuthorities() {
        return UserDto.from(
                SecurityUtil.getCurrentUsername()
                        .flatMap(userRepository::findOneWithAuthoritiesByUsername)
                        .orElseThrow(() -> new NotFoundMemberException("Member not found"))
        );
    }
}
