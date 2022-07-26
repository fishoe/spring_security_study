package com.example.securitywithjwt;

import com.example.securitywithjwt.request.AuthCredit;
import com.example.securitywithjwt.token.AuthToken;
import com.nimbusds.jose.util.StandardCharset;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.util.StreamUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final static String ALLOW_HTTP_METHOD = "POST";
    private final static String ALLOW_CONTENT_TYPE = "application/json";

    private final static String BASE_AUTH = "/api/auth";

    public AuthenticationFilter(AuthenticationManager authManager){
        super(authManager);
        setRequiresAuthenticationRequestMatcher(
                new OrRequestMatcher(
                        new AntPathRequestMatcher(BASE_AUTH)
                )
        );


        setAuthenticationSuccessHandler((request, response, authentication) -> {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
            }
        });
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException
    {
        if (!request.getMethod().equals(ALLOW_HTTP_METHOD)) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        if (!request.getContentType().equals(ALLOW_CONTENT_TYPE)) {
            throw new AuthenticationServiceException("content-type only allowed of application/json: " + request.getContentType());
        }
        String username;
        String password;
        try {
            String request_body = StreamUtils.copyToString(request.getInputStream(), StandardCharset.UTF_8);
            AuthCredit authInfo = AuthCredit.ConvertFromString(request_body);
            username = authInfo.getUsername().trim();
            password = (authInfo.getPassword() != null) ? authInfo.getPassword() : "" ;
        } catch ( Exception e ) {
            throw new BadCredentialsException(request.getContentType());
        }
        Authentication authentication = AuthToken.unauthenticated(username, password);
        return this.getAuthenticationManager().authenticate(authentication);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);
        SecurityContextHolder.setContext(context);
        chain.doFilter(request, response);
    }

}

