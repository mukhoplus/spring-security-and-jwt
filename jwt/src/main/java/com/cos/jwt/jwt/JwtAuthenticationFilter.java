package com.cos.jwt.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있음
 * /login 요청 -> Username과 Password를 POST 요청하면
 * UsernamePasswordAuthenticationFilter 동작
 * - 하지만 SecurityConfig에서 loginForm().disable()을 했기 때문에 이 필터를 SecurityConfig에 등록해주어야 함
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
        throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter 로그인 시도 중");

        /**
         * 1. username, password 받음
         * 2. 로그인 시도
         *  - authenticationManager가 로그인 시도
         *  - PrincipalDetailsService가 호출됨, loadUserByUsername() 함수 실행
         * 3. PrincipalDetails를 세션에 담음(권한 관리를 위해)
         * 4. JWT 토큰을 만들어 응답
         */

        return super.attemptAuthentication(request, response);
    }
}
