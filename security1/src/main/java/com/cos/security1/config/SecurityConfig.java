package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secure, prePostEnabled 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
            .antMatchers("/user/**").authenticated()
            .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
            .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
            .anyRequest().permitAll()
        .and()
            .formLogin()
            .loginPage("/loginForm")
            // .usernameParameter("customUsername")
            .loginProcessingUrl("/login") // /login이 호출되면 시큐리티가 낚아채서 대신 로그인을 진행한다.
            .defaultSuccessUrl("/")
        .and()
            .oauth2Login()
            .loginPage("/loginForm") // 로그인 완료 후의 후처리 -> 코드 X, 엑세스 토큰 + 사용자 프로필 정보 O
            .userInfoEndpoint()
            .userService(principalOauth2UserService);

        /**
         * 1. (인증)로그인 후 코드 받기
         * 2. (권한)엑세스 토큰 받기
         * 3. 정보 가져오기
         * 4. (처리)정보를 토대로 회원가입 자동 진행
         */
    }

}
