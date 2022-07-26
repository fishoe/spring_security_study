package com.example.securitywithjwt.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;

public class AuthToken extends AbstractAuthenticationToken {
    private final String principal;
    private String credentials;

    private AuthToken(String username, String password){
        super(null);
        principal = username;
        credentials = password;
        super.setAuthenticated(true);
    }

    private AuthToken(Authentication userAuthToken, Collection<? extends GrantedAuthority> authorities){
        super(authorities);
        principal = (String)userAuthToken.getPrincipal();
        credentials = (String)userAuthToken.getCredentials();
        super.setAuthenticated(true);
    }


    @Override
    public String getPrincipal() {
        return this.principal;
    }

    @Override
    public String getCredentials() {
        return this.credentials;
    }

    @Override
    public void setDetails(Object details){
        super.setDetails(details);
    }

    public static Authentication unauthenticated(
            String username, String password
    ){
        return new AuthToken(username, password);
    }

    public static Authentication authenticated(
            Authentication userAuthToken,
            Collection<? extends GrantedAuthority> authorities) {
        AuthToken auth = new AuthToken(userAuthToken, authorities);
        auth.setDetails("true love");
        return auth;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated,
                "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }
}

