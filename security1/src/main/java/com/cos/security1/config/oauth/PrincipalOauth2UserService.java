package com.cos.security1.config.oauth;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // 구글로 부터 받은 userRequest 데이터에 대한 후처리를 진행하는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // userRequest.getClientRegistration(); -> 클라이언트 요청 정보
        // userRequest.getAccessToken(); -> 로그인한 사용자의 엑세스 토큰
        // super.loadUser(userRequest).getAttributes(); -> 사용자 프로필 정보

        /**
         * 1. 구글 로그인 버튼 클릭
         * 2. 구글 로그인 창
         * 3. 로그인 완료
         * 4. Code 리턴(OAuth-Client Library)
         * 5. Access Token 요청
         * 6. userRequest 정보 반환
         * 7. loadUser 함수 호출
         * 8. 구글로 부터 회원 프로필 조회
         */
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 후처리: 회원가입
        String provider = userRequest.getClientRegistration().getRegistrationId();

        OAuth2UserInfo oAuth2UserInfo = null;
        if (provider.equals("google")) {
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (provider.equals("facebook")) {
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else if (provider.equals("naver")) {
            oAuth2UserInfo = new NaverUserInfo(oAuth2User.getAttribute("response"));
        } else {
            System.out.println("현재 구글/페이스북만 지원");
        }

        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode(username); // 의미 없기 때문에 아무런 값으로 지정해도 된다.
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        System.out.println(oAuth2User.getAttributes());
        User userEntity = userRepository.findByUsername(username);

        // 회원가입
        if (userEntity == null) {
            userEntity = User.builder()
                .username(username)
                .password(password)
                .email(email)
                .role(role)
                .provider(provider)
                .providerId(providerId)
                .build();

            userRepository.save(userEntity);
        }

        // UserDetails, OAuth2User 모두 처리 가능
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }

}
