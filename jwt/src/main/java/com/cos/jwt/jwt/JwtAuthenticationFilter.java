package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.hibernate.boot.model.source.spi.PluralAttributeElementSourceManyToAny;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.parameters.P;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

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

        // 1. username, password 받음
        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
            ObjectMapper om = new ObjectMapper(); // JSON 객체 파싱
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user); // User(id=0, username=mukho, password=muk, roles=null)

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            /* 2. 로그인 시도
               - authenticationManager가 로그인 시도
               - PrincipalDetailsService가 호출됨, loadUserByUsername() 함수 실행
             */
            Authentication authentication = authenticationManager.authenticate(authenticationToken); // 로그인 정보

            // 3. PrincipalDetails를 세션에 담음(권한 관리를 위해) - 로그인(인증) 됨
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료 : " + principalDetails.getUser().getUsername());
            /*
              - authentication 객체가 session 영역에 저장되어야 함 -> return
              - return의 이유 : 권한 관리를 security가 대신 해주기 때문
              - 굳이 JWT 토근을 사용하면서 세션을 만들 이유는 없으나, 단지 권한 처리 때문에 session에 넣어 준다.
             */
            // 4. JWT 토큰을 만들어 응답


            // 세션에 저장됨.
            return authentication;
        } catch(IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행된다.
    // -> JWT 토근을 생성해 요청한 사용자에게 반환해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
        FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행 : 인증 완료");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // Hash(No RSA) + Build-up Pattern
        String jwtToken = JWT.create()
            .withSubject("cos 토큰")
            .withExpiresAt(new Date(System.currentTimeMillis() + (1000 * 60 * 10))) // JwtProperties.EXPIRATION_TIME
            .withClaim("id", principalDetails.getUser().getId()) // 넣고 싶은 값을 다 넣으면 된다.
            .withClaim("username", principalDetails.getUser().getUsername())
            .sign(Algorithm.HMAC512("cos")); // JwtProperties.SECRET

        response.addHeader("Authorization", "Bearer " + jwtToken); // JWT 토큰을 헤더에 담아서 보내 준다.
    }
}
