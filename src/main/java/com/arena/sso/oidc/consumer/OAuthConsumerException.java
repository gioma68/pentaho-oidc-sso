package com.arena.sso.oidc.consumer;


import org.springframework.security.core.AuthenticationException;

public class OAuthConsumerException extends AuthenticationException {

    //~ Constructors ===================================================================================================

    public OAuthConsumerException(String message) {
        super(message);
    }

    public OAuthConsumerException(String message, Throwable cause) {
        super(message, cause);
    }
}
