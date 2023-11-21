package com.cos.security1.controller;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller // View를 return
public class IndexController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping({"", "/"})
    public String index() {
        // Mustache 기본 폴더 - src/main/resources/
        // ViewResolver 설정 - templates(prefix), .mustache(sufix)
        return "index"; // src/main/resources/templates/index.mustache 를 찾으나, WebMvcConfig에 의해 자동으로 매핑됨
    }

    @GetMapping("/user")
    public @ResponseBody String user() {
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    // 스프링 시큐리티가 우선됨 -> SecurityConfig 추가 후 비우선
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        user.setRole("ROLE_USER"); // 권한 부여

        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword); // 암호화

        userRepository.save(user); // 회원가입, 비밀번호가 암호화되지 않아 시큐리티로 로그인을 할 수 없다.

        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";
    }

    /* prePostEnabled : 이 메서드가 실행되기 전에 실행되며, role이 ROLE_ADMIN인 사용자의 요청만 허가한다.
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") // 조건 여러 개
    @PostAuthorize() -> 메서드 실행 후 실행. 잘 사용하지 않음.
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";
    }*/

}
