package com.cos.security1.auth;

import com.cos.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * 시큐리티는 /login 주소 요청이 오면 낚아채서 로그인을 진행한다.
 * 로그인 진행이 완료되면 security session을 만들어준다. (Security ContextHolder)
 * Object -> Authentication 타입 객체
 * - User 정보가 있어야 함
 *   User 오브젝트 타입 : UserDetails 타입 객체
 *
 * Security Session -> Authentication -> UserDetails(PrincipalDetails)
 */
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user;
    private Map<String, Object> attributes;

    // 일반 로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }

    // OAuth 로그인
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
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

    @Override
    public String getName() {
        return (String) this.attributes.get("sub");
    }
}
