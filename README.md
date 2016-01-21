#Pentaho SSO Extension using MITREid or WSO2 IS as IdP

This Pentaho SSO Extension is intended to provide Single Sign-On setup for Pentaho Platform using OAuth/OIDC "Authorization Code" grant flow with OS OAuth/OIDC certified server (this version was tested with MITREid 1.2.0 and WSO2 IS 5.1.0).  This project is mainly based on code and documentation, developed by **https://bitbucket.org/secureops/sops-pentaho**.

SSO extension allows to configure any number of Identity Providers, defining the list of Pentaho Roles for each "users channel" separately. Pentaho's own Authentication functionality can be also kept active if needed.

The extension is tested with: **Pentaho-Platform 5.4.0 CE**, **MITREid 1.2.0**, **WSO2 IS 5.1.0**. 

The instruction below intends that you have Pentaho platform installed and configured, one OAuth/OIDC server (MITREid or WSO2 IS).


##Compilation

To make it simpler, needed external libraries are included into embedded lib directory. All other dependences are related to Pentaho and Spring, and are available in assembled Pentaho platform. 

Compilation requires the following packages coming with Pentaho: 

-   Pentaho Core, API and Extensions packages (3 jars: **pentaho-platform-extensions-TRUNK-SNAPSHOT.jar**, **pentaho-platform-api-TRUNK-SNAPSHOT.jar**, **pentaho-platform-core-TRUNK-SNAPSHOT.jar**)
-   Spring Core (**spring-2.5.6.jar**)
-   Spring Security Core (**spring-security-core-2.0.5.RELEASE.jar**)
-   SLF4J (**slf4j-api-1.7.3.jar**)
-   ServletAPI (**servlet-api.jar** - is the only jar which is not available in Pentaho lib, but it is always coming with any Java Container)

In case of compiling the package using Apache Ant, please correct the needed paths in the **build.xml** provided (see the comments in build.xml file). 


##Deployment

Ant script releases **com.arena.sso-1.x.jar** file in the dist directory, together with needed libraries copied. To deploy the extension, all the jar files from **dist** directory should be simply copied into Pentaho lib directory. 


***
##Configuration

**1.** Configure *AuthenticationProcessingFilter*, *AuthenticationProvider*, *Consumer* and *AuthenticationEntryPoint* (this one was not required for OpenId because of embedded support by Spring) beans for OAuth in **applicationContext-spring-security.xml** like the following:
```xml
<bean id="oauthAuthenticationProcessingFilter" class="com.arena.sso.oidc.OAuthAuthenticationProcessingFilter">
	<property name="authenticationManager">
		<bean id="oauthAuthenticationManager" class="org.springframework.security.providers.ProviderManager">
			<property name="providers">
				<list>
					<ref local="oauthAuthenticationProvider" />
				</list>
			</property>
		</bean>
	</property>
	<property name="consumer" ref="oauthConsumer" />
	<property name="defaultTargetUrl" value="/Home" />
	<property name="authenticationFailureUrl" value="/Login?login_error=1" />
	<property name="targetUrlResolver">
		<ref local="targetUrlResolver" />	  
	</property>			
</bean>
```

```xml	
<bean id="oauthAuthenticationProvider" class="com.arena.sso.oidc.OAuthAuthenticationProvider">
	<property name="userDetailsService" ref="oauthUserDetailsService" />
</bean>	
```

```xml	
<bean id="oauthConsumer" class="com.arena.sso.oidc.consumer.OAuthConsumerImpl">
	<constructor-arg index="0" value="${oauth.redirectUrl}"/>
	<!-- custom property for MITRE-OPENID server -->
	<property name="mitreoidConsumerKey" value="${oauth.mitreoidConsumerKey}"/>
	<property name="mitreoidConsumerSecret" value="${oauth.mitreoidConsumerSecret}"/>
	<property name="mitreoidTokenRequestUri" value="${oauth.mitreoidTokenRequestUri}"/>
	<property name="mitreoidAccessTokenUri" value="${oauth.mitreoidAccessTokenUri}"/>
	<property name="mitreoidAuthenticationTokenUri" value="${oauth.mitreoidAuthenticationTokenUri}"/>
	<property name="mitreOpenIdClaim" value="${oauth.mitreOpenIdClaim}"/>
	<!-- end MITRE-OPENID server -->

	<!-- custom property for WSO2 IS-Oauth server -->
	<property name="wso2isConsumerKey" value="${oauth.wso2isConsumerKey}"/>
	<property name="wso2isConsumerSecret" value="${oauth.wso2isConsumerSecret}"/>
	<property name="wso2isTokenRequestUri" value="${oauth.wso2isTokenRequestUri}"/>
	<property name="wso2isAccessTokenUri" value="${oauth.wso2isAccessTokenUri}"/>
	<property name="wso2isAuthenticationTokenUri" value="${oauth.wso2isAuthenticationTokenUri}"/>
	<property name="wso2OpenIdClaim" value="${oauth.wso2OpenIdClaim}"/>
	<!-- end WSO2 IS-Oauth server -->		
</bean>
```

```xml
<bean id="oauthAuthenticationEntryPoint" class="com.arena.sso.oidc.OAuthAuthenticationEntryPoint">
	<property name="consumer" ref="oauthConsumer" />
</bean>
```

- Default *filterProcessesUrl* of *OAuthAuthenticationProcessingFilter* is ***/oauth/authenticate***. It can be overridden adding *filterProcessesUrl* property in the *oauthAuthenticationProcessingFilter* bean above. Please note that this URL is the one, which should be passed to Social's as a redirection (callback) URL. It should be also configured in the **oauth.properties** (see next point).


- *oauthAuthenticationProcessingFilter* and *oauthAuthenticationEntryPoint* defined above should be queued in the *FilterChainProxy* (property *filterInvocationDefinitionSource*) after Spring's *authenticationProcessingFilter*.


- In case that *targetUrlResolver* is defined as a nested bean under Spring's *authenticationProcessingFilter*, it should be taken out to be in global scope to be referenced from all *AuthenticationProcessingFilters* configured.
	
	

**2.** Add and configure **oauth.properties** file to manage configurable values (used by *OAuthConsumerImpl*) related to OAuth/OIDC server you are using (file example is provided in the **resources** folder). The file should be added to **pentaho-solutions/system** directory. 

Also add the following bean into **pentaho-spring-beans.xml** to make the property file data available for Spring IOC.

```xml
<bean class="org.pentaho.platform.config.SolutionPropertiesFileConfiguration">
	<constructor-arg value="oauth"/>
	<constructor-arg value="oauth.properties"/>
	<pen:publish as-type="INTERFACES"/>
</bean>
```

- The property *redirectUrl* in **oauth.properties** file should correspond to the one configures for Social Apps as redirect (callback) URL. It should also correspond to the URL processed by *oauthAuthenticationProcessingFilter*. Its structure is:
    ***http://<host>:<port>/<context>/<oauth\_authentication\_processing\_filter\_processes\_url>***



**3.** Configure *EnhancedHttpSessionReuseDetectionFilter* in **applicationContext-spring-security.xml** like the following:

```xml
<bean id="enhancedHttpSessionReuseDetectionFilter" class="com.secureops.sso.EnhancedHttpSessionReuseDetectionFilter">
	<property name="filterProcessesUrl" value="/j_spring_security_check" />
	<property name="sessionReuseDetectedUrl" value="/Login?login_error=2" />
	<property name ="ssoFilterProcessesUrls">
		<list>
			<value>/j_spring_oauth_security_check</value>
		</list>
	</property>
</bean>
```

- Please note that *ssoFilterProcessesUrls* property should contain all added SSO authentication URLs. So, if it was already added because some other IdP, just the value *j\_spring\_oauth\_security\_check* should be added into *ssoFilterProcessesUrls* list. 


**4.** Configure *SsoUserDetailsService* as *oauthUserDetailsService* bean in **pentahoObjects.spring.xml** like the following (refered from *OAuthAuthenticationProvider* configured above):

```xml
<bean id="oauthUserDetailsService" class="com.secureops.sso.SsoUserDetailsService">
	<constructor-arg>
		<ref local="cachingUserDetailsService"/>	  
	</constructor-arg>
	<property name="userRoleDao">
		<ref bean="userRoleDaoTxn" />
	</property>
	<property name="roles">
		<list>
			<value>Administrator</value>
			<value>Business Analyst</value>
		</list>	  
	</property>	
</bean>
```

- The list of *roles* should contain Pentaho role names, which should be assigned to the user signing-up using OAuth Authentication.

- Also please note that *userRoleDaoTxn* is given as default configuration (defined in **repository.spring.xml**) as *ProxyFactoryBean* (*userRoleDao* property of *SsoUserDetailsService*). 

> The issue is that *userRoleDaoProxy* bean, which is intended for production configuration, adds method level security using Spring AOP, which does not allow to *createUser* without administrative privilege. Alternatively, *userRoleDao* can be changed to *userRoleDaoProxy*, but *userRoleDaoMethodInterceptor* in **repository.spring.xml** should be adjusted to allow *createUser*, *setPassword* and *setUserDescription* methods invocation. 



**5.** Add OAuth authentication entry point and authentication URLs into *objectDefinitionSource* property of *filterInvocationInterceptor* (*FilterSecurityInterceptor*) like the following line in the CDATA section (in **applicationContext-spring-security.xml**):

```
\A/j_spring_oauth_security_check.*\Z=Anonymous,Authenticated
\A/oauth/authenticate.*\Z=Anonymous,Authenticated
```

- Place the lines after *j\_spring\_security\_check*


***

##SSO FrontEnd Configuration

**OIDC Login Processing URL **

```
http://<host>:<port>/<context>/j_spring_oauth_security_check
``` 

- required parameter is "***issuer***". The value should be one of the following:
	- *"mitreoid"*
	- *"wso2is"*

For example:
```
http://pentaho.server:pentaho_port/pentaho_context_root/j_spring_oauth_security_check?issuer=mitreoid
```
