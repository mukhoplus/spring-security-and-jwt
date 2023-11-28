package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.parameters.P;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 시큐리티가 filter를 가지고 있음.
 * - 그 중 BasicAuthenticationFilter는 권한이나 인증이 필요한 특정 주소를 요청 했을 때 무조건 거치게 된다.
 * - 만약 그렇지 않다면 해당 필터를 타지 않는다.
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소 요청이 있을 때 해당 필터를 타게 되므로, 헤더 - JWT 토큰 값을 확인하여 처리하자.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws IOException, ServletException {

        System.out.println("인증이나 권한이 필요한 요청");

        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
        System.out.println("jwtHeader : " + jwtHeader);

        // Header가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        // JWT 토큰 검증 -> 정상적인 사용자/요청인지 확인
        String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
        String username =
                JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();

        // 서명이 정상적으로 이루어짐
        if (username != null) {
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            // JWT 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어 준다.
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            // 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장 -> 로그인 됨
            SecurityContextHolder.getContext().setAuthentication(authentication); // 세션 공간


        }

        chain.doFilter(request, response);
    }
}
