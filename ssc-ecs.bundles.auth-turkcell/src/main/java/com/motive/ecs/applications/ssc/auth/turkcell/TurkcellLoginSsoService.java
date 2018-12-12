package com.motive.ecs.applications.ssc.auth.turkcell;

import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import com.motive.ecs.applications.ssc.security.core.LogoutHandler;
import com.motive.ecs.applications.ssc.security.core.SscAuthenticationDetails;
import com.motive.ecs.applications.ssc.security.core.SsoAuthentication;

/**
 * The implemented {@link AuthenticationProvider} which links the SSC-ECS
 * "/validate" step up with an SSO server made to validate the token provided,
 * and give a thumbs up/down on whether or not to allow entry into the SSC-ECS
 * services. <br>
 * Note that this is the only service needed to be provided for a customer whose
 * portal already populates the SSO token and when SSC-ECS only needs to
 * validate the token when crossing into SSC-ECS territory, allowing for a
 * bypass of any client interaction required for logging in with a
 * username/password. <br>
 * Pay very close attention to the beans.xml which exports this as an OSGi
 * service with very specific properties meant to flag this implementation as
 * the SSO {@link AuthenticationProvider} service for SSC-ECS.
 *
 *
 * @author otokat
 */

public class TurkcellLoginSsoService implements AuthenticationProvider, LogoutHandler {
	private static final String DTM_MANAGER_NAME = "com.sun.org.apache.xml.internal.dtm.DTMManager";
	private static final String DTM_MANAGER_VALUE = "com.sun.org.apache.xml.internal.dtm.ref.DTMManagerDefault";
	private static final Logger logger = Logger.getLogger(TurkcellLoginSsoService.class);
	private final static List<GrantedAuthority> SSC_AUTHORITIES = AuthorityUtils.createAuthorityList("SSC_user");
	private static Properties prop = null;

	static {
		// performance improvement:
		// https://issues.apache.org/jira/browse/XALANJ-2540
		System.setProperty(DTM_MANAGER_NAME, DTM_MANAGER_VALUE);
	}

	public TurkcellLoginSsoService() {
		logger.info("Constructing reference AuthenticationService to show SSO capabilities and integration");
	}

	public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			Authentication authentication) {

	}

	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		logger.debug("Reference bundle AuthenticationService received attempt to authenticate");

		SsoAuthentication ssoAuthentication = (SsoAuthentication) authentication;

		SscAuthenticationDetails details = (SscAuthenticationDetails) ssoAuthentication.getDetails();
		System.out.println("");
		if (details == null) {
			logger.error(
					"SSC Authentication Details are not included with the SsoAuthentication provided, violation of the authentication API");
			throw new IllegalArgumentException("SsoAuthentication must provide a non-null SscAuthenticationDetails");
		}

		HttpServletRequest request = details.getRequest();

		if (request == null) {
			logger.error(
					"HttpServletRequest are not included with the SsoAuthentication provided, violation of the authentication API");
			throw new IllegalArgumentException(
					"SsoAuthentication must provide a non-null SscAuthenticationDetails containing a non-null HttpServletRequest");
		}

		logger.info("BASE64 Encoding started");
		logger.info(request.getParameter("subscriberId").replace(" ", "+"));
		String decryptedToken = KeyTool.decrypt(request.getParameter("subscriberId").replace(" ", "+").getBytes());

		logger.info("decryptedToken: " + decryptedToken);
		// logger.info("subscriberId: " + request.getParameter("subscriberId"));
		
		logger.info("validateToken: " + KeyTool.validateToken(decryptedToken));
		
		if (!"".equals(decryptedToken) && KeyTool.validateToken(decryptedToken)) {

			String subscriberId = decryptedToken.split("##")[0];
			logger.info("Valid cookie received, deliving enabled username password authentication token");

			UsernamePasswordAuthenticationToken resultToken = new UsernamePasswordAuthenticationToken(subscriberId,
					null, SSC_AUTHORITIES);

			HashMap<String, String> attributes = new HashMap<String, String>();
			
			attributes.put("subscriberId", subscriberId);
			resultToken.setDetails(attributes);

			return resultToken;
		}
		return null;
	}

	public boolean supports(Class<? extends Object> aClass) {
		logger.info("Received sample SSO reference request to test if we support object type " + aClass);
		return SsoAuthentication.class.isAssignableFrom(aClass);
	}
}
