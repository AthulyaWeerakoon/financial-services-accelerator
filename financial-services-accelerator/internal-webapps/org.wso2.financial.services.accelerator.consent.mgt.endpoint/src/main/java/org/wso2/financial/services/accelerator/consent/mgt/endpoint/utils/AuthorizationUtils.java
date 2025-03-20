package org.wso2.financial.services.accelerator.consent.mgt.endpoint.utils;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.financial.services.accelerator.common.exception.FinancialServicesException;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;


/**
 * Utils class for Authorization management endpoint.
 */
public class AuthorizationUtils {

    private static final Log log = LogFactory.getLog(AuthorizationUtils.class);
    private static final String API_ENDPOINT = "/api/identity/auth/v1.1/data/OauthConsentKey/";
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    );

    /**
     * @param sessionDataKey sessionDataKey consent used for fetching sensitive data. Refer
     *                       <a href="https://is.docs.wso2.com/en/5.9.0/develop/authentication-data-api/">
     *                           Authentication Data API</a>
     */
    public static String fetchSensitiveData(String sessionDataKey) throws FinancialServicesException {
        try {

            // Sanitize sessionDataKey
            if (!isValidUUID(sessionDataKey)) {
                log.error("sessionDataKeyConsent was invalid.");
                throw new FinancialServicesException("Invalid sessionDataKeyConsent.");
            }

            // NOTE: Need to make SCHEME:HOST:PORT dynamic
            String requestUri = "https://localhost:9446" + API_ENDPOINT + sessionDataKey;
            URIBuilder uriBuilder = new URIBuilder(requestUri);

            HttpGet httpGet = new HttpGet(uriBuilder.build().toString());
            httpGet.setHeader("Accept", "application/json");
            httpGet.setHeader("Connection", "keep-alive");

            CloseableHttpClient httpClient = MutualTLSHTTPClientUtils.getMutualTLSHttpsClient();
            HttpResponse response = null;
            response = httpClient.execute(httpGet);
            InputStream in;

            int responseCode = response.getStatusLine().getStatusCode();
            String responseString;
            if (responseCode == HttpURLConnection.HTTP_OK) { // 200
                in = response.getEntity().getContent();
            } else {
                log.error("Sensitive data retrieval from Identity Server failed with HTTP response: " +
                        responseCode);
                throw new FinancialServicesException("Failed to fetch sensitive data from Identity Server.");
            }

            responseString =  IOUtils.toString(in, String.valueOf(StandardCharsets.UTF_8));

            httpClient.close();

            return responseString;
        } catch (Exception e) {
            log.error("Sensitive data retrieval from Identity Server failed.");
            throw new FinancialServicesException("Failed to fetch sensitive data from Identity Server.", e);
        }
    }

    /**
     * Resolves the username for a given user ID by fetching the user data and extracting the username.
     *
     * @param userId The UUID of the user whose username is to be retrieved.
     * @return The extracted username, or null if not found.
     * @throws FinancialServicesException If the user data cannot be fetched or parsed.
     */
    public static String resolveUsernameFromUserId(String userId) throws FinancialServicesException {
        try {
            // Call the fetchUserData method to retrieve the user data JSON
            String jsonResponse = fetchUserData(userId);

            // Parse the JSON response
            JSONObject jsonObject = new JSONObject(jsonResponse);

            // Extract "userName" field
            return jsonObject.optString("userName", null);
        } catch (Exception e) {
            log.error("Failed to resolve username for user ID", e);
            throw new FinancialServicesException("Error resolving username for user ID.", e);
        }
    }

    /**
     * Fetches user data from the WSO2 SCIM endpoint using mutual TLS authentication.
     * @param userId The UUID of the user whose data is to be retrieved.
     * @return A JSON-formatted string containing the user's data.
     * @throws FinancialServicesException If an error occurs during the HTTP request or response processing.
     */
    public static String fetchUserData(String userId) throws FinancialServicesException {
        try {
            String userUUID = userId.split("@")[0];

            // Sanitize userId
            if (!isValidUUID(userUUID)) {
                log.error("User ID is invalid.");
                throw new FinancialServicesException("Invalid userId.");
            }

            // Construct the request URI dynamically
            String requestUri = "https://localhost:9446/wso2/scim/Users/" + userUUID;
            URIBuilder uriBuilder = new URIBuilder(requestUri);

            HttpGet httpGet = new HttpGet(uriBuilder.build().toString());
            httpGet.setHeader("Accept", "application/json");
            httpGet.setHeader("Connection", "keep-alive");
            httpGet.setHeader("Authorization",
                    "Basic " + Base64.getEncoder().encodeToString(
                            ("is_admin@wso2.com" + ":" + "wso2123").getBytes(StandardCharsets.UTF_8)
                            // NOTE: Make dynamic
                    ));

            // Create an HTTP client with mutual TLS
            CloseableHttpClient httpClient = MutualTLSHTTPClientUtils.getMutualTLSHttpsClient();
            HttpResponse response = httpClient.execute(httpGet);
            InputStream in;

            int responseCode = response.getStatusLine().getStatusCode();
            String responseString;
            if (responseCode == HttpURLConnection.HTTP_OK) { // 200
                in = response.getEntity().getContent();
            } else {
                log.error("User data retrieval failed with HTTP response: " + responseCode);
                throw new FinancialServicesException("Failed to fetch user data.");
            }

            responseString = IOUtils.toString(in, StandardCharsets.UTF_8);
            httpClient.close();

            return responseString;
        } catch (Exception e) {
            log.error("User data retrieval failed.", e);
            throw new FinancialServicesException("Failed to fetch user data.", e);
        }
    }

    /**
     * @param jsonString JSON object as raw text, fetched from post request.
     * @return nested map of key-value (String/Object) pairs
     */
    public static Map<String, Object> getFetchedSensitiveDataMap(String jsonString) {
        JSONObject jsonObject = new JSONObject(jsonString);
        return parseFetchedSensitiveJSONObject(jsonObject);
    }

    /**
     * @param jsonObject JSON object to be parsed into a map.
     * @return nested map of key-value (String/Object) pairs
     */
    private static Map<String, Object> parseFetchedSensitiveJSONObject(JSONObject jsonObject) {
        Map<String, Object> map = new HashMap<>();

        Iterator<String> keys = jsonObject.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            Object value = jsonObject.get(key);

            if (value instanceof JSONObject) {
                map.put(key, parseFetchedSensitiveJSONObject((JSONObject) value));
            } else if (value instanceof JSONArray) {
                map.put(key, parseFetchedSensitiveJSONArray((JSONArray) value));
            } else {
                map.put(key, value);
            }
        }

        return map;
    }

    /**
     *
     * @param jsonArray JSON array to be parsed into a map.
     * @return nested map of key-value (Integer/Object) pairs
     */
    private static Object parseFetchedSensitiveJSONArray(JSONArray jsonArray) {
        if (jsonArray.isEmpty()) {
            return jsonArray;
        }

        Map<Integer, Object> listMap = new HashMap<>();
        for (int i = 0; i < jsonArray.length(); i++) {
            Object value = jsonArray.get(i);

            if (value instanceof JSONObject) {
                listMap.put(i, parseFetchedSensitiveJSONObject((JSONObject) value));
            } else if (value instanceof JSONArray) {
                listMap.put(i, parseFetchedSensitiveJSONArray((JSONArray) value));
            } else {
                listMap.put(i, value);
            }
        }

        return listMap;
    }

    /**
     *
     * @param query URL query to be parsed to an object
     * @return parsed query as a map of parameters
     * @throws UnsupportedEncodingException if passed string is not utf-8 encoded
     */
    public static ConcurrentMap<String, String[]> extractQueryParams(String query) throws UnsupportedEncodingException,
            UnsupportedEncodingException {
        ConcurrentMap<String, String[]> queryParams = new ConcurrentHashMap<>();

        if (query != null) {
            String[] pairs = query.split("&");

            for (String pair : pairs) {
                String[] keyValue = pair.split("=");

                if (keyValue.length == 2) {
                    String key = URLDecoder.decode(keyValue[0], "UTF-8");
                    String value = URLDecoder.decode(keyValue[1], "UTF-8");

                    queryParams.put(key, new String[]{value});
                }
            }
        }
        return queryParams;
    }

    /**
     * @param uuid string to verify if UUID
     * @return is UUID or not
     */
    public static boolean isValidUUID(String uuid) {
        return uuid != null && UUID_PATTERN.matcher(uuid).matches();
    }
}
