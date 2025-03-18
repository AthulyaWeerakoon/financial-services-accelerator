package org.wso2.financial.services.accelerator.consent.mgt.endpoint.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.financial.services.accelerator.common.constant.FinancialServicesConstants;
import org.wso2.financial.services.accelerator.common.exception.FinancialServicesException;
import org.wso2.financial.services.accelerator.common.util.JWTUtils;
import org.wso2.financial.services.accelerator.consent.mgt.extensions.common.ConsentExtensionConstants;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.ConcurrentMap;

/**
 * Data class for Authorizations.
 * This class contains methods for fetching and managing sensitive data required for /retrieve/{session-data-key}
 * endpoint.
 */
public class AuthorizationData {

    private static final Log log = LogFactory.getLog(AuthorizationData.class);
    private Map<String, Serializable> sensitiveDataMap;
    private ConcurrentMap<String, String[]> paramMap;
    private OAuth2Parameters oAuth2Parameters;

    public AuthorizationData(String sessionDataKey) throws FinancialServicesException { loadSensitiveData(sessionDataKey); }

    /**
     * @param sessionDataKey sessionDataKeyConsent used to fetch sensitive data.
     * @throws FinancialServicesException when data fetch fails
     */
    private void loadSensitiveData(String sessionDataKey) throws FinancialServicesException {

        // Fetch sensitive data
        String sensitiveDataRaw = AuthorizationUtils.fetchSensitiveData(sessionDataKey);

        // Parse sensitive data to JSON
        JSONObject sensitiveDataJSON = new JSONObject(sensitiveDataRaw);

        // Extract query parameters
        ConcurrentMap<String, String[]> paramMap;
        try {
            paramMap = AuthorizationUtils.extractQueryParams(sensitiveDataJSON.getString("spQueryParams"));
        }
        catch (UnsupportedEncodingException e) {
            log.error("\"spQueryParams\" object in retrieved payload is not utf-8 encoded");
            throw new FinancialServicesException("Unsupported encoding in fetched sensitive data.");
        }

        // Extract request object body
        JSONObject JWTbody;
        try {
            JWTbody = new JSONObject(JWTUtils.decodeRequestJWT(paramMap.get("request")[0],
                    FinancialServicesConstants.JWT_BODY));
        }
        catch (ParseException e){
            log.error("JWT parse failure");
            throw new FinancialServicesException("Failed to decode JWT.");
        }

        // Build sensitiveDataMap
        sensitiveDataMap = buildSensitiveDataMap(sensitiveDataJSON);

        // Build paramMap
        paramMap.put("sessionDataKey", new String[]{sessionDataKey});
        this.paramMap = paramMap;

        // Build oAuth2Parameters
        oAuth2Parameters = buildOAuth2Parameters(sensitiveDataJSON, paramMap, JWTbody);
    }

    /**
     * @param sensitiveDataJSON sensitiveDataJSON from which sensitiveDataMap is built
     * @return sensitiveDataMap
     */
    private Map<String, Serializable> buildSensitiveDataMap(JSONObject sensitiveDataJSON) {
        Map<String, Serializable> sensitiveDataMap = new HashMap<>();

        String[] keys = {
                "scopeMetadata",
                ConsentExtensionConstants.IS_ERROR,
                "application",
                "scope",
                "spQueryParams",
                "loggedInUser",
                "tenantDomain"
        };

        for (String key : keys) {
            if (ConsentExtensionConstants.IS_ERROR.equals(key)) {
                if (sensitiveDataJSON.has(key)) {
                    sensitiveDataMap.put(key, sensitiveDataJSON.getBoolean(key));
                } else {
                    sensitiveDataMap.put(key, Boolean.FALSE);
                }
            } else {
                if (sensitiveDataJSON.has(key)) {
                    Object value = sensitiveDataJSON.get(key);
                    if (value instanceof Serializable) {
                        sensitiveDataMap.put(key, (Serializable) value);
                    } else {
                        sensitiveDataMap.put(key, value.toString());
                    }
                }
            }
        }

        return sensitiveDataMap;
    }

    /**
     * @param sensitiveDataJSON JSON object of sensitive data
     * @param paramMap query parameter map
     * @param JWTBody decoded request body
     * @return oAuth2Parameters object
     */
    private OAuth2Parameters buildOAuth2Parameters(JSONObject sensitiveDataJSON,
                                                   ConcurrentMap<String, String[]> paramMap, JSONObject JWTBody) {
        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
        oAuth2Parameters.setApplicationName(sensitiveDataJSON.getString("application"));
        oAuth2Parameters.setRedirectURI(paramMap.get("redirect_uri")[0]);
        oAuth2Parameters.setState(paramMap.get("state")[0]);
        oAuth2Parameters.setResponseType(paramMap.get("response_type")[0]);
        oAuth2Parameters.setResponseType(paramMap.get("client_id")[0]);
        oAuth2Parameters.setNonce(paramMap.get("nonce")[0]);
        oAuth2Parameters.setPrompt(paramMap.get("prompt")[0]);
        oAuth2Parameters.setTenantDomain(sensitiveDataJSON.getString("tenantDomain"));
        oAuth2Parameters.setEssentialClaims(String.valueOf(JWTBody.getJSONObject("claims")));
        oAuth2Parameters.setSessionDataKey(paramMap.get("sessionDataKey")[0]);
        oAuth2Parameters.setLoginTenantDomain(sensitiveDataJSON.getString("loggedInUser")
                .split("@")[1].trim());

        // Set scopes
        HashSet<String> scopes = new HashSet<>(Arrays.asList(paramMap.get("scope")[0].trim().split(" ")));
        oAuth2Parameters.setScopes(scopes);

        // NOTE: Set consent required scopes are set to be same as scopes
        oAuth2Parameters.setConsentRequiredScopes(scopes);

        return  oAuth2Parameters;
    }

    /**
     * @return sensitiveDataMap
     */
    public Map<String, Serializable> getSensitiveDataMap() {
        return sensitiveDataMap;
    }

    /**
     * @return paramMap
     */
    public ConcurrentMap<String, String[]> getParamMap() {
        return paramMap;
    }

    /**
     * @return oAuth2Parameters
     */
    public OAuth2Parameters getOAuth2Parameters() {
        return oAuth2Parameters;
    }
}
