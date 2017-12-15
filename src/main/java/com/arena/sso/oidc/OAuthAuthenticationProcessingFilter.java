package com.arena.sso.oidc;

import com.arena.sso.oidc.consumer.OAuthConsumer;
import com.arena.sso.oidc.consumer.OAuthConsumerException;
import com.arena.sso.oidc.consumer.UserData;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * Filter processes request coming from OAuth provider and delegating to the OauthConsumer. After the OAuthPreAuthenticationToken
 * is obtained, authentication providers are asked to authenticate it.
 *
 */
public class OAuthAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

    //~ Static fields ==================================================================================================

    private static final String DEFAUL_URL = "/oauth/authenticate";

    //~ Instance fields ================================================================================================

    private OAuthConsumer consumer;
    
    public OAuthAuthenticationProcessingFilter()
    {
        super(DEFAUL_URL);
    }
    
    protected OAuthAuthenticationProcessingFilter(RequestMatcher requiresAuthenticationRequestMatcher)
    {
        super(requiresAuthenticationRequestMatcher);
    }
    
    //~ Methods ========================================================================================================
    
    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException
    {
        OAuthPreAuthenticationToken preAuthToken;
        try {
            UserData identity = consumer.handleAuthenticationRequest(httpServletRequest);
            preAuthToken = new OAuthPreAuthenticationToken(identity);
        } catch (Exception e) {
            throw new AuthenticationServiceException("Consumer error", e);
        }
    
        preAuthToken.setDetails(authenticationDetailsSource.buildDetails(httpServletRequest));
    
        // delegate to the auth provider
        return getAuthenticationManager().authenticate(preAuthToken);
    }

    public OAuthConsumer getConsumer() {
        return consumer;
    }

    public void setConsumer(OAuthConsumer consumer) {
        this.consumer = consumer;
    }
}
