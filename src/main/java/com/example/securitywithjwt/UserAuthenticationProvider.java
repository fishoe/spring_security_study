package com.example.securitywithjwt;

import com.example.securitywithjwt.token.AuthToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException
    {
        // UserCredit 객체를 사용해서 검증
        // 현재는 학습과정이라 생략함
        String username = authentication.getName();
        String password = (String)authentication.getCredentials();

        boolean isAuthenticated = ( username.equals("lovemachine") &&
                password.equals("kingofmen"));

        if (isAuthenticated){
            authentication = AuthToken.authenticated(
                    authentication,authentication.getAuthorities());
        }else
            throw new BadCredentialsException("wrong authentication information");
        return authentication;
    }


    // 토큰이 Provider를 지원하는지 여부
    @Override
    public boolean supports(Class<?> authentication) {
        return AuthToken.class.isAssignableFrom(authentication);
    }

}
