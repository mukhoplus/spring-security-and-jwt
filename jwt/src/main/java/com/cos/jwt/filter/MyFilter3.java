package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // Make JWT Token <- ID/PW가 정상적으로 넘어와 로그인되면, 토큰을 만들어 응답해야 함.
        // 이후에는 만들어진/넘어온 토큰이 정상적인지만 검증하면 됨.(RSA, HS256)
        if (req.getMethod().equals("POST")) {
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터 3");

            if (headerAuth.equals("cos")) { // 해당 POST 요청 - 헤더의 Authorization 값이 mukho 일 때만 정상 동작
                chain.doFilter(req, res);
            } else { // 아니라면 미인증 <- 이를 JWT로 하면 된다.
                PrintWriter out = res.getWriter();
                out.println("인증안됨");
            }
        }

    }
}
