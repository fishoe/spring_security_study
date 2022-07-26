package com.example.securitywithjwt;

import com.example.securitywithjwt.token.JwtToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
public class JwtAuthenticationManager implements AuthenticationManager {
    private final JwtDecoder jwtDecoder;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException
    {
        String bearerToken = (String)authentication.getCredentials();
        Jwt jwt;
        try {
            jwt = jwtDecoder.decode(bearerToken);
        } catch (Exception e){
            throw new BadCredentialsException("invalid token");
        }

        String issuer = jwt.getClaimAsString("iss");
        List<GrantedAuthority> authorities = getAuthorities(jwt);

        Authentication authToken;
        String name = jwt.getClaimAsString("name");
        authToken = JwtToken.authenticated(issuer, null, authorities, name);

        return authToken;
    }

    private List<GrantedAuthority> getAuthorities(Jwt jwt){
        List<String> scope = jwt.getClaimAsStringList("scope");
        return new ArrayList<>();
    }
}