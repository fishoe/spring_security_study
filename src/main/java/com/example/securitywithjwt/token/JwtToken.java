package com.example.securitywithjwt.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtToken extends AbstractAuthenticationToken {
    private final String principal;
    private final Long credentials;

    private JwtToken(String issuer, Long provider_uid, Collection<? extends GrantedAuthority> authorities){
        super(authorities);
        principal = issuer;
        credentials = provider_uid;
        super.setAuthenticated(true);
    }

    @Override
    public String getPrincipal() {
        return this.principal;
    }

    @Override
    public Long getCredentials() {
        return this.credentials;
    }

    @Override
    public void setDetails(Object details){
            super.setDetails(details);
    }

    public static JwtToken authenticated(
            String issuer, Long personal_id,
            Collection<? extends GrantedAuthority> authorities,
            String details) {
        JwtToken auth = new JwtToken(issuer, personal_id, authorities);
        auth.setDetails(details);
        return auth;
    }
}
