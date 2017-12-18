package com.arena.sso;

import com.arena.sso.oidc.OAuthUserDetailsService;
import org.pentaho.platform.api.engine.security.userroledao.IUserRoleDao;
import org.pentaho.platform.api.engine.security.userroledao.NotFoundException;
import org.pentaho.platform.engine.core.system.PentahoSessionHolder;
import org.pentaho.platform.engine.core.system.PentahoSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Implements UserDetailsService for SSO authentication mechanism.
 * The approach is to wrap intended PentahoUserDetailsService adding user creation functionality for users signing-up
 * through integrated Identity Provider Service.
 * <p>
 * Normally, Pentaho Security denys user creation if authorized session does not belong to Admin user. To enable
 * "auto registration" it is required to reduce security here. So, UserRoleDao security interception should allow
 * <code>createUser, setPassword, setUserDescription</code> methods invocation.
 * See "SSO authentication" integration guide for details.
 */
public class SsoUserDetailsService implements OAuthUserDetailsService, InitializingBean {

    private static final Logger log = LoggerFactory.getLogger(SsoUserDetailsService.class);
    //~ Instance fields ================================================================================================

    private UserDetailsService pentahoUserDetailsService;

    private IUserRoleDao userRoleDao;

    private String[] roles;

    //~ Constructor ====================================================================================================

    public SsoUserDetailsService(UserDetailsService pentahoUserDetailsService) {
        this.pentahoUserDetailsService = pentahoUserDetailsService;
    }

    //~ Methods ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        if(roles == null) {
            roles = new String[] {};
        }
    }

    /**
     * {@inheritDoc}
     *
     * Creates new user if there is no one available in the repository by given user name.
     * Should be used only for SSO authentication.
     */
    @Override
    public UserDetails loadUserByUsernameWithRoles(String username, String[] roles) throws UsernameNotFoundException, DataAccessException {
        UserDetails user;
        

        try {
            for (String role: roles)
            {
                if (userRoleDao.getRole(null, role) == null)
                {
                    userRoleDao.createRole(null, role, "", new String[]{});
                }
            }
            userRoleDao.setUserRoles(null, username, roles);
            user = pentahoUserDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException|NotFoundException e) {

            if ( userRoleDao == null ) {
                userRoleDao = PentahoSystem.get(IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession());
            }
            
            String password = PasswordGenerator.generate();
            userRoleDao.createUser(null, username, password, "", roles );
            user = pentahoUserDetailsService.loadUserByUsername(username);
        }

        return user;
    }
    
    @Override
    public UserDetails loadUserByUsername(String user) throws UsernameNotFoundException
    {
        return loadUserByUsernameWithRoles(user, this.roles);
    }

    public void setUserRoleDao(IUserRoleDao userRoleDao) {
        this.userRoleDao = userRoleDao;
    }

    public void setRoles(String[] roles) {
        this.roles = roles;
    }
}
