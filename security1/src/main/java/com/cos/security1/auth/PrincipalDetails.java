package com.cos.security1.auth;

import com.cos.security1.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

/**
 * 시큐리티는 /login 주소 요청이 오면 낚아채서 로그인을 진행한다.
 * 로그인 진행이 완료되면 security session을 만들어준다. (Security ContextHolder)
 * Object -> Authentication 타입 객체
 * - User 정보가 있어야 함
 *   User 오브젝트 타입 : UserDetails 타입 객체
 *
 * Security Session -> Authentication -> UserDetails(PrincipalDetails)
 */
public class PrincipalDetails implements UserDetails {

    private User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    // 해당 User의 권한을 반환하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 미구현
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 미구현
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 미구현
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 미구현
    @Override
    public boolean isEnabled() {
        return true;
    }
}
