package com.arena.sso.oidc;

import org.springframework.security.providers.preauth.PreAuthenticatedAuthenticationToken;

/**
 * The only need to specify special type of AuthenticationToken for OAuth pre-authentication purposes.
 */
public class OAuthPreAuthenticationToken extends PreAuthenticatedAuthenticationToken {

    public OAuthPreAuthenticationToken(String aPrincipal) {
        super(aPrincipal, "");
    }

}
