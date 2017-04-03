/**
 * Copyright 2017 the Procter & Gamble Company
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *  
 */
package com.pg.security.ping.adapter.sp;

import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.AuthnAdapterDescriptor;
import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RegExValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.saml20.adapter.sp.authn.SpAuthenticationAdapter;
import org.sourceid.saml20.adapter.sp.authn.SsoContext;

import com.pingidentity.locale.LocaleUtil;
import com.pingidentity.sdk.locale.LanguagePackMessages;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import com.pingidentity.sdk.template.TemplateRendererUtilException;

/**
 * This class is implemented as an SP adapter. Another use case would be to
 * append a MYSAPSSO2 cookie to requests coming through the IdP adapter policy
 * stack.
 * 
 * @author hesse.cd
 *
 */
public class SpSAPAdapter implements SpAuthenticationAdapter {

	private Log log = LogFactory.getLog(this.getClass());

	private static String TYPE = "SAP MYSAPSSO2 SP Adapter";

	private static String SAP_USERNAME = "sap_username";

	// This value must be configured/matched in the "Authentication Policy
	// Adapter Mappings"
	private static final String DEFAULT_REDIRECT_URL = "http://sapgui.com";

	private static final String MYSAPSSO2 = "MYSAPSSO2";
	private static final String KEYSTORE_ALIAS = "Keystore Alias";
	private static final String TARGET_SYSTEM_CODEPAGE = "Target System Codepage";
	private static final String SOURCE_SYSTEM_ID = "Source System ID";
	private static final String SOURCE_SYSTEM_CLIENT = "Source System Client";
	private static final String TICKET_DURATION_HOURS = "Ticket Duration In Hours";
	private static final String TICKET_DURATION_MINS = "Ticket Duration In Minutes";
	private static final String TEMPLATE_FILE_NAME = "SAP Selection Template";

	private static final String DEFAULT_TARGET_SYSTEM_CODEPAGE = "4103";
	private static final String DEFAULT_SOURCE_SYSTEM_ID = "PNGFED01";
	private static final String DEFAULT_SOURCE_SYSTEM_CLIENT = "000";
	private static final String DEFAULT_TICKET_DURATION_HOURS = "8";
	private static final String DEFAULT_TICKET_DURATION_MINS = "0";
	private static final String DEFAULT_TEMPLATE_FILE_NAME = "sap.system.selector.template.html";
	private static final String DEFAULT_LANGUAGE_PACK_NAME = "sap-system-selector-template";
	private static final String LANGUAGE_PACK_VARIABLE_NAME = "sapTokenAdapterTemplateMessages";

	private String keystoreAlias = null;
	private String targetSystemCodepage = null;
	private String sourceSystemId = null;
	private String sourceSystemClient = null;
	private String ticketDurationHours = null;
	private String ticketDurationMins = null;
	private String templateFileName = null;

	/**
	 * Hold on to an instance so we don't have to rebuild it every time
	 * getAdapterDescriptor() is called.
	 * 
	 * See the initDescriptor() method for an example of creating an
	 * AuthnAdapterDescriptor
	 */
	private AuthnAdapterDescriptor authnAdapterDesc = initDescriptor();

	/**
	 * a value that will be set via GUI configuration when
	 * configure(Configuration configuration) is called
	 */

	public Serializable createAuthN(SsoContext ssoContext, HttpServletRequest request, HttpServletResponse response,
			String resumePath) throws AuthnAdapterException, IOException {

		log.info("******** " + TYPE + " ********");

		String sapUsername = ((AttributeValue) ssoContext.getSubjectAttrs().get(SAP_USERNAME)).getValue();
		log.info("*" + sapUsername + "*");

		TicketCreator tc = new TicketCreator(keystoreAlias, sapUsername, sourceSystemId, targetSystemCodepage,
				sourceSystemClient, Integer.parseInt(ticketDurationHours), Integer.parseInt(ticketDurationMins));
		String ticket = tc.generateTicket();

		log.info("User: " + sapUsername + " -> " + MYSAPSSO2 + "=" + ticket);

		// TODO: The default targetResource should be a configuration parameter
		// For now the assumption is that the DEFAULT_REDIRECT_URL is
		// manually entered in the adapter
		// mapping config.
		if (ssoContext.getTargetResourceUrl().equals(DEFAULT_REDIRECT_URL)) {
			// Means SAP GUI
			log.info("No target resource found, assuming SAP GUI.");
			renderForm(request, response, resumePath, sapUsername, ticket);
		} else {
			log.info("Target resource found, assuming SAP Portal/Web Applicaiton redirect.");
			// Put the ticket in a cookie, and redirect to TargetResource
			Cookie cookie = new Cookie(MYSAPSSO2, ticket);
			cookie.setSecure(false); // determines whether the cookie should
										// only be sent using a secure protocol,
										// such as HTTPS or SSL
										// assuming we may redirect to HTTP
										// sites
			cookie.setPath("/"); // The cookie is visible to all the pages in
									// the directory you specify, and all the
									// pages in that directory's sub directories
			String domain = null;
			try {
				domain = getHostName(ssoContext.getTargetResourceUrl());

				log.info(domain);
				cookie.setDomain(domain);
				response.addCookie(cookie);

				response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
				response.setHeader("Location", ssoContext.getTargetResourceUrl());
			} catch (URISyntaxException e) {
				throw new AuthnAdapterException("TargetResource URL is invalid");
			}
		}

		return true;
	}

	/**
	 * 
	 * @param url
	 * @return
	 * @throws URISyntaxException
	 */
	public String getHostName(String url) throws URISyntaxException {
		URI uri = new URI(url);
		String hostname = uri.getHost();
		// to provide fault proof result, check if not null then return only
		// hostname, without www.
		if (hostname == null) {
			throw new URISyntaxException(url, "URL string is not a valid URL");
		}
		return hostname.startsWith("www.") ? hostname.substring(4) : hostname;
	}

	/**
	 *
	 * This is a helper method that renders the template form via
	 * {@link TemplateRendererUtil} class.
	 *
	 * @param req
	 *            the HttpServletRequest can be used to read cookies,
	 *            parameters, headers, etc. Accessing the HttpSession from the
	 *            request is not recommended and doing so is deprecated. Use
	 *            {@link org.sourceid.saml20.adapter.state.SessionStateSupport}
	 *            as an alternative.
	 * @param resp
	 *            the HttpServletResponse can be used to set cookies before
	 *            continuing the SSO request.
	 * @param resumeURL
	 *            the relative URL that the user agent needs to return to, if
	 *            the implementation of this method invocation needs to operate
	 *            asynchronously. If this method operates synchronously, this
	 *            parameter can be ignored. The resumePath is the full path
	 *            portion of the URL - everything after hostname and port. If
	 *            the hostname, port, or protocol are needed, they can be
	 *            derived using the HttpServletRequest.
	 * 
	 * @param emailAddressDomainNameFieldBlank
	 *            indicates whether the user has provided any input or not.
	 */
	private void renderForm(HttpServletRequest req, HttpServletResponse resp, String resumeURL, String sapUsername,
			String ticket) {
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("url", resumeURL);

		// This code creates a SAP Shortcut file
		// see https://wiki.scn.sap.com/wiki/display/ABAP/SAPGUI+shortcuts
		StringBuilder bOutput = new StringBuilder();

		bOutput.append("[System]");
		bOutput.append("<br/>");

		bOutput.append("Name=");
		bOutput.append("???");
		bOutput.append("<br/>");

		bOutput.append("Client=");
		bOutput.append("???");
		bOutput.append("<br/>");

		bOutput.append("[User]");
		bOutput.append("<br/>");

		bOutput.append("Name=");
		bOutput.append(sapUsername);
		bOutput.append("<br/>");

		bOutput.append(("at=\"MYSAPSSO2=" + ticket + "\""));
		bOutput.append("<br/>");
		bOutput.append("Language=EN");
		bOutput.append("<br/>");

		bOutput.append("[Function]");
		bOutput.append("<br/>");
		bOutput.append("Title=SAP GUI");
		bOutput.append("<br/>");
		bOutput.append("Command=");
		bOutput.append("<br/>");

		bOutput.append("[Options]");
		bOutput.append("<br/>");

		bOutput.append("Reuse=0");
		bOutput.append("<br/>");

		params.put("filecontent", bOutput.toString());

		// Load sample-authn-selector-email-template.properties file and store
		// it in the map
		Locale userLocale = LocaleUtil.getUserLocale(req);
		LanguagePackMessages lpm = new LanguagePackMessages(DEFAULT_LANGUAGE_PACK_NAME, userLocale);
		params.put(LANGUAGE_PACK_VARIABLE_NAME, lpm);

		try {
			TemplateRendererUtil.render(req, resp, this.templateFileName, params);
		} catch (TemplateRendererUtilException e) {
			log.error("Error rendering the " + this.templateFileName + " template.", e);
		}
	}

	/**
	 * This implementation doesn't do anything here
	 */

	public boolean logoutAuthN(Serializable authnBean, HttpServletRequest req, HttpServletResponse resp,
			String resumePath) throws AuthnAdapterException, IOException {
		return true;
	}

	/**
	 * This implementation doesn't do anything here
	 */
	public String lookupLocalUserId(HttpServletRequest req, HttpServletResponse resp, String partnerIdpEntityId,
			String resumePath) throws AuthnAdapterException, IOException {
		return null;
	}

	/**
	 * The PingFederate server will invoke this method on your adapter
	 * implementation to discover metadata about the implementation. This
	 * included the adapter's attribute contract and a description of what
	 * configuration fields to render in the GUI. <br/>
	 * <br/>
	 * Your implementation of this method should return the same
	 * AuthnAdapterDescriptor object from call to call - behaviour of the system
	 * is undefined if this convention is not followed.
	 * 
	 * @return an AuthnAdapterDescriptor object that describes this adapter
	 *         implementation.
	 */
	public AuthnAdapterDescriptor getAdapterDescriptor() {
		return authnAdapterDesc;
	}

	/**
	 * This method is called by the PingFederate server to push configuration
	 * values entered by the administrator via the dynamically rendered GUI
	 * configuration screen in the PingFederate administration console. Your
	 * implementation should use the {@link Configuration} parameter to
	 * configure its own internal state as needed. <br/>
	 * <br/>
	 * Each time the PingFederate server creates a new instance of your plugin
	 * implementation this method will be invoked with the proper configuration.
	 * All concurrency issues are handled in the server so you don't need to
	 * worry about them here. The server doesn't allow access to your plugin
	 * implementation instance until after creation and configuration is
	 * completed.
	 * 
	 * @param configuration
	 *            the Configuration object constructed from the values entered
	 *            by the user via the GUI.
	 */

	public void configure(Configuration configuration) {
		keystoreAlias = configuration.getFieldValue(KEYSTORE_ALIAS);
		targetSystemCodepage = configuration.getFieldValue(TARGET_SYSTEM_CODEPAGE);
		sourceSystemId = configuration.getFieldValue(SOURCE_SYSTEM_ID);
		sourceSystemClient = configuration.getFieldValue(SOURCE_SYSTEM_CLIENT);
		ticketDurationHours = configuration.getFieldValue(TICKET_DURATION_HOURS);
		ticketDurationMins = configuration.getFieldValue(TICKET_DURATION_MINS);
		templateFileName = configuration.getFieldValue(TEMPLATE_FILE_NAME);
	}

	/**
	 * Build the AuthnAdapterDescriptor for this adapter implementation.
	 * 
	 * @return a descriptor for this adapter
	 */
	private AuthnAdapterDescriptor initDescriptor() {
		// TODO: If this becomes a Ping offered adapter, you may want to give
		// the option of specifying
		// SAP SID's (system id's) and client numbers as drop downs. You will
		// have to tie them together however
		// e.g. "NP3 - 100", "NP3 - 200", "NP2 - 400"

		// Create an AdapterConfigurationGuiDescriptor that will tell
		// PingFederate how to render a configuration
		// GUI screen and how to validate the user input
		String description = "SP Adapter that will generate a MYSAPSSO2 cookie for SAP Netweaver ABAP and SAP Netweaver Java systems.";
		AdapterConfigurationGuiDescriptor adapterConfGuiDesc = new AdapterConfigurationGuiDescriptor(description);

		TextFieldDescriptor textFieldTargetSystemCodepage = new TextFieldDescriptor(TARGET_SYSTEM_CODEPAGE,
				"For Unicode SAP systems, the system code page depends on the platform byte order:  4103 (UTF-16 LE) 4102 (UTF-16 BE)");
		textFieldTargetSystemCodepage.addValidator(new RequiredFieldValidator());
		textFieldTargetSystemCodepage.addValidator(new RegExValidator("^([0-9]){4}$"));
		textFieldTargetSystemCodepage.setDefaultValue(DEFAULT_TARGET_SYSTEM_CODEPAGE);
		adapterConfGuiDesc.addField(textFieldTargetSystemCodepage);

		TextFieldDescriptor textFieldSourceSystemId = new TextFieldDescriptor(SOURCE_SYSTEM_ID,
				"The source system ID is the 8 character system ID for this Ping Federate system.  It must match the value you give when configuring the ACL in the STRUSTSSO2 transaction in SAP.  It does NOT need to match the target system client (e.g. NP1)!");
		textFieldSourceSystemId.addValidator(new RequiredFieldValidator());
		textFieldSourceSystemId.addValidator(new RegExValidator("^([a-zA-Z0-9]){8}$"));
		textFieldSourceSystemId.setDefaultValue(DEFAULT_SOURCE_SYSTEM_ID);
		adapterConfGuiDesc.addField(textFieldSourceSystemId);

		TextFieldDescriptor textFieldSourceSystemClient = new TextFieldDescriptor(SOURCE_SYSTEM_CLIENT,
				"The source system client is the 3 digit code you want to give this Ping Federate system.  It will show up in the STRUSTSSO2 transaction in SAP.  It does NOT need to match the target system client!");
		textFieldSourceSystemClient.addValidator(new RequiredFieldValidator());
		textFieldSourceSystemClient.addValidator(new RegExValidator("^([0-9]){3}$"));
		textFieldSourceSystemClient.setDefaultValue(DEFAULT_SOURCE_SYSTEM_CLIENT);
		adapterConfGuiDesc.addField(textFieldSourceSystemClient);

		TextFieldDescriptor textFieldTicketDurationHours = new TextFieldDescriptor(TICKET_DURATION_HOURS,
				"Configure the value of the ticket duration in hours, from 0 - 24.");
		textFieldTicketDurationHours.addValidator(new RequiredFieldValidator());
		textFieldTicketDurationHours.addValidator(new RegExValidator("^([0-9]){1,2}$"));
		textFieldTicketDurationHours.setDefaultValue(DEFAULT_TICKET_DURATION_HOURS);
		adapterConfGuiDesc.addField(textFieldTicketDurationHours);

		TextFieldDescriptor textFieldTicketDurationMins = new TextFieldDescriptor(TICKET_DURATION_MINS,
				"Configure the value of the ticket duration in minutes, from 0 - 59.");
		textFieldTicketDurationMins.addValidator(new RequiredFieldValidator());
		textFieldTicketDurationMins.addValidator(new RegExValidator("^([0-9]){1,2}$"));
		textFieldTicketDurationMins.setDefaultValue(DEFAULT_TICKET_DURATION_MINS);
		adapterConfGuiDesc.addField(textFieldTicketDurationMins);

		TextFieldDescriptor textFieldTemplateFileName = new TextFieldDescriptor(TEMPLATE_FILE_NAME,
				"The template file name stored in the templates directory.");
		textFieldTemplateFileName.addValidator(new RequiredFieldValidator());
		textFieldTemplateFileName.setDefaultValue(DEFAULT_TEMPLATE_FILE_NAME);
		adapterConfGuiDesc.addField(textFieldTemplateFileName);

		TextFieldDescriptor textFieldKeystoreAlias = new TextFieldDescriptor(KEYSTORE_ALIAS,
				"The alias corresponding to the certificate you want to sign the MYSAPSSO2 cookie with.  It should be a SHA1withDSA 1024 type certificate.  Go to Server Settings -> Signing & Decryption Keys & Certificates -> click on the signing certificate you want to use, and copy the alias value here.");
		textFieldKeystoreAlias.addValidator(new RequiredFieldValidator());
		adapterConfGuiDesc.addField(textFieldKeystoreAlias);

		// A set of attribute names are the attribute contract for the adapter
		Set<String> attributeContract = new HashSet<String>();
		attributeContract.add(SAP_USERNAME);

		return new AuthnAdapterDescriptor(this, TYPE, attributeContract, true, adapterConfGuiDesc);
	}
}
