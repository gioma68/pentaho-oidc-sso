package com.arena.sso.oidc.consumer;

import javax.servlet.http.HttpServletRequest;


public interface OAuthConsumer {

    /**
     * Handles login request and return url for redirection to identity provider.
     * @param request HttpServletRequest
     * @return return url for redirection to identity provider.
     * @throws OAuthConsumerException in case of any problem occurs during processing
     */
    public String handleLoginRequest(HttpServletRequest request) throws OAuthConsumerException;


    /**
     * Handles response coming from identity provider, and return authentication token.
     * @param request request coming from identity provider.
     * @return  user identity.
     * @throws OAuthConsumerException in case of any problem occurs during processing
     */
    public String handleAuthenticationRequest(HttpServletRequest request) throws OAuthConsumerException;
	
}
