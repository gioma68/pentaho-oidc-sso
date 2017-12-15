package com.arena.sso.oidc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;

/**
 * @author reminder63
 * Date: 14.12.2017
 * Time: 16:11
 */
public class OAuthLogoutHandler implements LogoutHandler
{
    private static final Logger log = LoggerFactory.getLogger(OAuthLogoutHandler.class);
    
    @Override
    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication)
    {
        Arrays.stream(httpServletRequest.getCookies()).forEach(cookie -> {
            cookie.setMaxAge(0);
            log.info("Cookie '{}' will be remove", cookie.getName());
        });
    }
}
