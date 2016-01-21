#Pentaho SSO Extension 

Pentaho SSO Extension is intended to provide Single Sign-On setup for Pentaho Platform. It supports SAML, OpenID and OAuth (for Facebook, Google, Twitter & LinkedIn) authentications.

SSO extension allows to configure any number of Identity Providers, defining the list of Pentaho Roles for each "users channel" separately. Pentaho's own Authentication functionality can be also kept active if needed.

The extension is tested with the version "Pentaho-Platform 5.4.0 CE". 

The instruction below intends that you have Pentaho platform installed and configured.


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

Ant script releases **com.secureops.sso-1.x.jar** file in the dist directory, together with needed libraries copied. To deploy the extension, all the jar files from **dist** directory should be simply copied into Pentaho lib directory. 


***
##OpenID Configuration

**1.** Configure *AuthenticationProcessingFilter*, *AuthenticationProvider* and  *Consumer* beans for OpenID in **applicationContext-spring-security.xml** like the following:
```xml
<bean id="openIdAuthenticationProcessingFilter"
	class="org.springframework.security.ui.openid.OpenIDAuthenticationProcessingFilter">
	<property name="authenticationManager">
		<bean id="openidAuthenticationManager" 
			class="org.springframework.security.providers.ProviderManager">
			<property name="providers">
				<list>
					<ref local="openIdAuthenticationProvider" />
				</list>
			</property>
		</bean>
	</property>
	<property name="consumer">
		<ref local="enhancedOpenIdConsumer4Java" />
	</property>		
	<property name="claimedIdentityFieldName" value="openid_identifier" />
	<property name="authenticationFailureUrl" value="/Login?login_error=1" />
	<property name="defaultTargetUrl" value="/Home" />
	<property name="targetUrlResolver">
		<ref local="targetUrlResolver" />	  
	</property>			
</bean>
```

```xml
<bean id="openIdAuthenticationProvider" class="org.springframework.security.providers.openid.OpenIDAuthenticationProvider">
	<property name="userDetailsService" ref="openIdUserDetailsService" />
</bean>
```

```xml
<bean id="enhancedOpenIdConsumer4Java" class="com.secureops.sso.openid.EnhancedOpenID4JavaConsumer">
	<property name="providersDomainMapping">
		<map>
			<entry key="app.onelogin.com/openid" value="ol" />
			<entry key="myopenid.com" value="moid" />
			<entry key="livejournal.com" value="lj" />
			<entry key="openid.aol.com" value="aol" />
			<entry key="wordpress.com" value="wp" />
			<entry key="blogspot.com" value="bs" />
			<entry key="openid.claimid.com" value="cid" />
			<entry key="pip.verisignlabs.com" value="pip" />
			<entry key="clickpass.com/public" value="cp" />
			<entry key="google.com/profiles" value="gp" />
			<entry key="flickr.com" value="fl" />
			<entry key="vox.com/" value="vox" />
			<entry key="myspace.com" value="ms" />	
			<entry key="ww4.musicpictures.com/openid" value="mp" />				
			<entry key="myid.net" value="mid" />				
		</map>
	</property>
</bean>
```


- *openIdAuthenticationProcessingFilter* defined above should be queued in the FilterChainProxy (property *filterInvocationDefinitionSource*) after Spring's *authenticationProcessingFilter*.

- In case that *targetUrlResolver* is defined as a nested bean under Spring's *authenticationProcessingFilter*, it should be taken out to be in global scope to be referenced from all *AuthenticationProcessingFilters* configured. 

>

- **UserName Generation**: For the case when OpenID Provider does not provide email information about the user signing-up, SSO Extension generates a user name out of user's Identity URL. In order to do not have it really long, EnhancedOpenID4JavaConsumer (see above) provides ability to substitute URL parts in the Identity URL by defined short keywords. This is what *providersDomainMapping* property is meant for. 

    The following example demonstrates the logic of user name generation. E.g. Identity URL is ***https://app.onelogin.com/openid/myorganization.com/hunter.thompson***. The user name generation will do the following: 

    - remove *https://*
    - substitute *app.onelogin.com/openid* by *ol* (see configuration of EnhancedOpenID4JavaConsumer)
    - replace all remaining (**/**) symbols by dot symbols (**.**)
 
    The user name will be generate as ***ol.myorganization.com.hunter.thompson***. 
	
	

**2.** Configure *EnhancedHttpSessionReuseDetectionFilter* in **applicationContext-spring-security.xml** like the following:
```xml
<bean id="enhancedHttpSessionReuseDetectionFilter" class="com.secureops.sso.EnhancedHttpSessionReuseDetectionFilter">
	<property name="filterProcessesUrl" value="/j_spring_security_check" />
	<property name="sessionReuseDetectedUrl" value="/Login?login_error=2" />
	<property name ="ssoFilterProcessesUrls">
		<list>
			<value>/j_spring_openid_security_check</value>
<!-- 
			<value>/j_spring_oauth_security_check</value>
			<value>/j_spring_saml_security_check</value>
			<value>/saml/sso/admin</value>
			<value>/saml/sso/user</value>
			<value>/saml/sso/ba</value> 
-->
		</list>
	</property>
</bean>
```

- Please note that *ssoFilterProcessesUrls* property should contain all added SSO authentication URLs. So, if it was already added because some other IdP, just the value *j\_spring\_openid\_security\_check* should be added into *ssoFilterProcessesUrls* list. 

- *enhancedHttpSessionReuseDetectionFilter* should be queued in the *FilterChainProxy* (property *filterInvocationDefinitionSource*) after instead of Pentaho's *httpSessionReuseDetectionFilter*.



**3.** Configure *SsoUserDetailsService* as *openIdUserDetailsService* bean in **pentahoObjects.spring.xml** like the following (refered from *OpenIDAuthenticationProvider* configured above):
```xml
<bean id="openIdUserDetailsService" class="com.secureops.sso.SsoUserDetailsService">
	<constructor-arg>
		<ref local="cachingUserDetailsService"/>	  
	</constructor-arg>
	<property name="userRoleDao">
		<ref bean="userRoleDaoTxn" />
	</property>
	<property name="roles">
		<list>
			<value>Power User</value>
			<value>Report Author</value>
		</list>	  
	</property>	
</bean>
```

- The list of *roles* should contain Pentaho role names, which should be assigned to the user signing-up using OpenId Authentication. 

- Also please note that *userRoleDaoTxn* is given as default configuration (defined in **repository.spring.xml**) as *ProxyFactoryBean* (*userRoleDao* property of *SsoUserDetailsService*). 

> The issue is that *userRoleDaoProxy* bean, which is intended for production configuration, adds method level security using Spring AOP, which does not allow to *createUser* without administrative privilege. Alternatively, *userRoleDao* can be changed to *userRoleDaoProxy*, but *userRoleDaoMethodInterceptor* in **repository.spring.xml** should be adjusted to allow *createUser*, *setPassword* and *setUserDescription* methods invocation.


	
**4.** Add OpenId authentication url into *objectDefinitionSource* property of *filterInvocationInterceptor* (*FilterSecurityInterceptor*) like the following line in the CDATA section (in **applicationContext-spring-security.xml**):

```
\A/j_spring_openid_security_check.*\Z=Anonymous,Authenticated
```

- Place the line after *j\_spring\_security\_check*


***

##OAuth Configuration

**1.** Configure *AuthenticationProcessingFilter*, *AuthenticationProvider*, *Consumer* and *AuthenticationEntryPoint* (this one was not required for OpenId because of embedded support by Spring) beans for OAuth in **applicationContext-spring-security.xml** like the following:
```xml
<bean id="oauthAuthenticationProcessingFilter" class="com.secureops.sso.oauth.OAuthAuthenticationProcessingFilter">
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
<bean id="oauthAuthenticationProvider" class="com.secureops.sso.oauth.OAuthAuthenticationProvider">
	<property name="userDetailsService" ref="oauthUserDetailsService" />
</bean>	
```

```xml	
<bean id="oauthConsumer" class="com.secureops.sso.oauth.consumer.OAuthConsumerImpl">
	<constructor-arg index="0" value="${oauth.redirectUrl}"/>
	
	<property name="googleConsumerKey" value="${oauth.googleConsumerKey}" />
	<property name="googleConsumerSecret" value="${oauth.googleConsumerSecret}" />
	
	<property name="facebookConsumerKey" value="${oauth.facebookConsumerKey}" />
	<property name="facebookConsumerSecret" value="${oauth.facebookConsumerSecret}" />
			
	<property name="linkedinConsumerKey" value="${oauth.linkedinConsumerKey}" />
	<property name="linkedinConsumerSecret" value="${oauth.linkedinConsumerSecret}" />
	
	<property name="twitterConsumerKey" value="${oauth.twitterConsumerKey}" />
	<property name="twitterConsumerSecret" value="${oauth.twitterConsumerSecret}" />		
</bean>
```

```xml
<bean id="oauthAuthenticationEntryPoint" class="com.secureops.sso.oauth.OAuthAuthenticationEntryPoint">
	<property name="consumer" ref="oauthConsumer" />
</bean>
```

- Default *filterProcessesUrl* of *OAuthAuthenticationProcessingFilter* is ***/oauth/authenticate***. It can be overridden adding *filterProcessesUrl* property in the *oauthAuthenticationProcessingFilter* bean above. Please note that this URL is the one, which should be passed to Social's as a redirection (callback) URL. It should be also configured in the **oauth.properties** (see next point).


- *oauthAuthenticationProcessingFilter* and *oauthAuthenticationEntryPoint* defined above should be queued in the *FilterChainProxy* (property *filterInvocationDefinitionSource*) after Spring's *authenticationProcessingFilter*.


- In case that *targetUrlResolver* is defined as a nested bean under Spring's *authenticationProcessingFilter*, it should be taken out to be in global scope to be referenced from all *AuthenticationProcessingFilters* configured.
	
	

**2.** Add and configure **oauth.properties** file to manage configurable values (used by *OAuthConsumerImpl*) related to Social App (file example is provided in the **resources** folder). The file should be added to **pentaho-solutions/system** directory. 

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
<!-- 
			<value>/j_spring_openid_security_check</value>
-->
			<value>/j_spring_oauth_security_check</value>
<!-- 
			<value>/j_spring_saml_security_check</value>
			<value>/saml/sso/admin</value>
			<value>/saml/sso/user</value>
			<value>/saml/sso/ba</value> 
-->
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

##SAML Configuration

SAML implementation allows to configure more than one IdP at the same time. This can be used to manage access rights, so that users having access to different IdP services get different Pentaho Roles in the system. 

To make multi IdP configuration clear, there is a naming convention to use some ***issuer\_key*** keyword to identify each set of filters, URLs, etc. In case of using several IdPs to separate access rights, the keys can be named like "*user*", "*admin*", "*business_analyst*" (or just *ba*), etc.  

So, please NOTE that you should replace the *{issuer\_key}* and *{issuerKey}* variables used in the examples below by some keys identifying particular IdP you configure. 


**1.** Initialize needed OpenSAML library adding *bootstrap* and *parserPool* beans into **applicationContext-spring-security.xml** file like the following:

```xml
<!-- Initialization of OpenSAML library-->
<bean id="bootstrap" class="org.opensaml.DefaultBootstrap" init-method="bootstrap" lazy-init="false" />

<!-- XML parser pool needed for OpenSAML parsing -->
<bean id="parserPool" class="org.opensaml.xml.parse.BasicParserPool"/>
```

**2.** Create self-signed sertificate and SP Metadata file (see SAML documentation for details). The example files (**samlKeystore.jks** & **sp-metadata.xml**) from **resources** folder can be used for testing purposes.

Copy **samlKeystore.jks** & **sp-metadata.xml** files into **pentaho-solutions/system** directory.   


**3.** Configure SAMLMetadataProvider bean in the **applicationContext-spring-security.xml** like the following:

```xml
<bean id="metadata" class="com.secureops.sso.saml.metadata.SAMLMetadataProvider" depends-on="bootstrap">
	<constructor-arg index="0">
		<list>			
			<bean class="org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider" init-method="initialize">
				<constructor-arg index="0">
					<value type="java.io.File">sp-metadata.xml</value>
				</constructor-arg>
				<property name="parserPool" ref="parserPool"/>
			</bean>				
			<bean class="org.opensaml.saml2.metadata.provider.HTTPMetadataProvider" init-method="initialize">
				<constructor-arg index="0">
					<value type="java.lang.String">https://app.onelogin.com/saml/metadata/353490</value>
				</constructor-arg>
				<constructor-arg index="1">
					<value type="int">5000</value>
				</constructor-arg>
				<property name="parserPool" ref="parserPool"/>
			</bean>
		</list>
	</constructor-arg>
	<constructor-arg index="1">
		<map>				
			<entry key="{issuer_key}" value="https://app.onelogin.com/saml/metadata/353490" />
		</map>
	</constructor-arg>
	<constructor-arg index="2" value="http://pentaho.server:pentaho_port/pentaho_context_root" />
</bean>
```

- First constructor argument (by index 0) should set list of metadata providers so that *SAMLMetadataProvider* could load SP and IdP metadata files (in case of multi-IdP setup, one provider per each IdP should be configured). 

- Second constructor argument, should provide a map of *{issuer\_key}* values used for each IdP to the value of *"entityID"* attribute defined in IdP metadata file. Usually, IdP services use metadata URL for this pupose. 

- Constructor argument under index 2 should set an own *"entityID"* used in SP metadata file. We used Pentaho service home URL for this purpose (see particular IdP metadata file). 


**4.** Configure *AuthenticationProcessingFilter*, *AuthenticationProvider*, *Consumer* and *AuthenticationEntryPoint* beans for SAML in **applicationContext-spring-security.xml** like the following:

```xml
<bean id="samlProcessingFilter4{issuerKey}" class="com.secureops.sso.saml.SAMLProcessingFilter" depends-on="bootstrap">
	<property name="authenticationManager">
		<bean id="samlAuthenticationManager4{issuerKey}" class="org.springframework.security.providers.ProviderManager">
			<property name="providers">
				<list>
					<ref local="samlAuthenticationProvider4{issuerKey}" />
				</list>
			</property>
		</bean>
	</property>
	<property name="authenticationFailureUrl" value="/Login?login_error=1" />
	<property name="defaultTargetUrl" value="/Home" />
	<property name="filterProcessesUrl" value="/saml/sso/{issuer_key}"/>
	<property name="consumer" ref="samlConsumer" />
	<property name="targetUrlResolver">
		<ref local="targetUrlResolver" />	  
	</property>		
</bean>
```

```xml
<bean id="samlAuthenticationProvider4{issuerKey}" class="com.secureops.sso.saml.SAMLAuthenticationProvider">
	<property name="consumer" ref="samlConsumer" />     
	<property name="userDetailsService" ref="samlUserDetailsService4{issuerKey}" />
</bean>
```

```xml
<bean id="samlConsumer" class="com.secureops.sso.saml.consumer.SamlConsumerImpl" depends-on="bootstrap">
	<constructor-arg index="0" ref="metadata" />
	<constructor-arg index="1" value="samlKeystore.jks" /> 
	<constructor-arg index="2" value="pentahoSamlKey" /> 
	<constructor-arg index="3" value="storePass123" /> 
	<constructor-arg index="4" value="keyPass123" /> 
	<property name="parser" ref="parserPool" />
</bean> 
```

```xml
<bean id="samlEntryPoint" class="com.secureops.sso.saml.SAMLEntryPoint" depends-on="samlConsumer">
	<property name="consumer" ref="samlConsumer" />
</bean>
```

- *SamlConsumer* arguments should be adjusted according to the Keystore file generated:
    - arguments under index 2 is an Alias of the public/private keys generated for keystore;
    - argument 3 is the store password to access Keystore file;
    - argument 4 is the key password to access generated public/private keys for given Allias.
	
- *samlEntryPoint* and all processingFilters (*samlAuthenticationProvider4{issuerKey}*) defined above should be queued in the *FilterChainProxy* (property *filterInvocationDefinitionSource*) after Spring's *authenticationProcessingFilter*.

- In case that *targetUrlResolver* is defined as a nested bean under Spring's *authenticationProcessingFilter*, it should be taken out to be in global scope to be referenced from all *AuthenticationProcessingFilters* configured.
	
**5.** Configure *EnhancedHttpSessionReuseDetectionFilter* in **applicationContext-spring-security.xml** like the following:

```xml
<bean id="enhancedHttpSessionReuseDetectionFilter" class="com.secureops.sso.EnhancedHttpSessionReuseDetectionFilter">
	<property name="filterProcessesUrl" value="/j_spring_security_check" />
	<property name="sessionReuseDetectedUrl" value="/Login?login_error=2" />
	<property name ="ssoFilterProcessesUrls">
		<list>
<!-- 
			<value>/j_spring_openid_security_check</value>
			<value>/j_spring_oauth_security_check</value>
-->
			<value>/j_spring_saml_security_check</value>
			<value>/saml/sso/{issuer_key}</value>
		</list>
	</property>
</bean>
```

- Please note that *ssoFilterProcessesUrls* property should contain all added SSO authentication URLs. So, if it was already added because some other IdP, just the value *j\_spring\_saml\_security\_check* and all SAML processing URLs (*/saml/sso/{issuer\_key}*) should be added into *ssoFilterProcessesUrls* list. 


**6.** Configure *SsoUserDetailsService* as *oauthUserDetailsService* bean in **pentahoObjects.spring.xml** like the following (refered from *SAMLAuthenticationProvider*'s configured above):

```xml
<bean id="samlUserDetailsService4{issuerKey}" class="com.secureops.sso.SsoUserDetailsService">
	<constructor-arg>
		<ref local="cachingUserDetailsService"/>	  
	</constructor-arg>
	<property name="userRoleDao">
		<ref bean="userRoleDaoTxn" />
	</property>
	<property name="roles">
		<list>
			<value>Business Analyst</value>
			<value>Special Role This Issuer</value>
		</list>	  
	</property>	
</bean>
```

- The list of *roles* should contain Pentaho role names, which should be assigned to the user signing-up using particula SAML IdP.

- Also please note that *userRoleDaoTxn* is given as default configuration (defined in **repository.spring.xml**) as *ProxyFactoryBean* (*userRoleDao* property of *SsoUserDetailsService*). 

> The issue is that *userRoleDaoProxy* bean, which is intended for production configuration, adds method level security using Spring AOP, which does not allow to *createUser* without administrative privilege. Alternatively, *userRoleDao* can be changed to *userRoleDaoProxy*, but *userRoleDaoMethodInterceptor* in **repository.spring.xml** should be adjusted to allow *createUser*, *setPassword* and *setUserDescription* methods invocation. 


**7.** Add SAML authentication entry point and authentication URLs into *objectDefinitionSource* property of *filterInvocationInterceptor* (*FilterSecurityInterceptor*) like the following line in the CDATA section (in **applicationContext-spring-security.xml**):

```
\A/j_spring_saml_security_check.*\Z=Anonymous,Authenticated
\A/saml/sso/{issuer_key}.*\Z=Anonymous,Authenticated
```

- Place the lines after *j\_spring\_security\_check*

**8.** Adjust *Location* attribute of *AssertionConsumerService* in sp-metadata.xml file, like the following:

```xml
	<md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="http://pentaho.server:pentaho_port/pentaho_context_root/saml/sso/{issuer_key}"
        index="0" isDefault="true"/>
```

- There can be several *AssertionConsumerService*s configured in the metadata file. Please NOTE to set those under different indexes, and have just one as a default (see *index* and *isDefault* attributes).


##Additional SAML IdP Configuration steps

Basically, the usage of *issuer\_key* & *issuerKey* variables hints the elements which should be added for additional IdP. 

Define new *issuerKey* to name new bean groups and *issuer\_key* to use in the addressing, and update the configuration according to the summary below:

**1.** Configure additional *SAMLProcessingFilter*, *SAMLAuthenticationProvider* and *SsoUserDetailsService* beans, using new keys (use the examples presented above). 

- The list of *roles* for new *samlUserDetailsService4{newIssuerKey}* bean should contain Pentaho role names, which should be assigned to the user signing-up using this IdP.
 
 
**2.** Update *SAMLMetadataProvider* to include new *MetadataProvider* bean loading new IdP metadata file.  

- Add new list item to the argument under index 0 like the following:

```xml
<bean class="org.opensaml.saml2.metadata.provider.HTTPMetadataProvider" init-method="initialize">
	<constructor-arg index="0">
		<value type="java.lang.String">https://idp.provider/saml/metadata/url</value>
	</constructor-arg>
	<constructor-arg index="1">
		<value type="int">5000</value>
	</constructor-arg>
	<property name="parserPool" ref="parserPool"/>
</bean>
```

- add a map entry for *{new\_issuer\_key}* with the value used by new IdP as the value of *"entityID"* attribute defined in IdP metadata file. Usually, IdP services use metadata URL for this pupose (see particular IdP metadata file): 

```
	<entry key="{new_issuer_key}" value="https://idp.provider/saml/metadata/url/which_is__usually_equal_to_entity_id" />
```


**3.** Add URL '/saml/sso/{new\_issuer\_key}' in list property *ssoFilterProcessesUrls* into *enhancedHttpSessionReuseDetectionFilter*.


**4.** Add URL '/saml/sso/{new\_issuer\_key}' into *objectDefinitionSource* property of *filterInvocationInterceptor* (*FilterSecurityInterceptor*) like the following line in the CDATA section (in **applicationContext-spring-security.xml**):

```
\A/saml/sso/{new_issuer_key}.*\Z=Anonymous,Authenticated
```

**5.** Add *AssertionConsumerService* with adjusted *Location* attribute into **sp-metadata.xml**:

```xml
<md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="http://pentaho.server:pentaho_port/pentaho_context_root/saml/sso/{new_issuer_key}"
        index="1" isDefault="false"/>
```		

- There can be several *AssertionConsumerService*s configured in the metadata file. Please NOTE to set those under different indexes, and have just one as a default (see *index* and *isDefault* attributes).


***

##SSO FrontEnd Configuration

There is no any constraint for FrontEnd implementation. SSO Extension just requires the following authentication requests: 

**1.** OpenID Login Processing URL 

```
http://<host>:<port>/<context>/j_spring_openid_security_check
``` 

- required parameter is "***openid\_identifier***". The value should correspond to the OpenID provider's Server EndPoint URL (like *https://www.google.com/accounts/o8/id* for Google) or User's personal OpenID URL (like *https://<username>.wordpress.com* for WordPress users) 


**2.** OAuth Login Processing URL 

```
http://<host>:<port>/<context>/j_spring_oauth_security_check
``` 

- required parameter is "***social***". The value should be one of the following:
	- *"google"*
	- *"facebook"*
	- *"linkedin"*
	- *"twitter"*
	
For example:
```
http://pentaho.server:pentaho_port/pentaho_context_root/j_spring_oauth_security_check?social=google
```

**3.** SAML Login Processing URL 

```
http://<host>:<port>/<context>/j_spring_saml_security_check
``` 

- required parameter is "***saml\_issuer\_key***". The value should correspond to the value of *{issuer\_key}* configured for SSO Extension
	



