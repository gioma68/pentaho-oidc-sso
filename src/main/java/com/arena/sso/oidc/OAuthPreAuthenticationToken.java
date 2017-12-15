package com.arena.sso.oidc;

import com.arena.sso.oidc.consumer.UserData;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * The only need to specify special type of AuthenticationToken for OAuth pre-authentication purposes.
 */
public class OAuthPreAuthenticationToken extends PreAuthenticatedAuthenticationToken {

    private UserData userData;
    
    public OAuthPreAuthenticationToken(UserData userData) {
        super(userData.getUserName(), "");
        this.userData = userData;
    }
    
    public UserData getUserData()
    {
        return userData;
    }
}
