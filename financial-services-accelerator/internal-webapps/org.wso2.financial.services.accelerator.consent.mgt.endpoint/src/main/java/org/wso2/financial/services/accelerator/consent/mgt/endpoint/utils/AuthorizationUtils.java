package org.wso2.financial.services.accelerator.consent.mgt.endpoint.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.financial.services.accelerator.common.exception.FinancialServicesException;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class AuthorizationUtils {

    private static final Log log = LogFactory.getLog(AuthorizationUtils.class);
    private static final String API_ENDPOINT = "/api/identity/auth/v1.1/data/OauthConsentKey";

    /**
     * @param sessionDataKey sessionDataKey consent used for fetching sensitive data. Refer
     *                       <a href="https://is.docs.wso2.com/en/5.9.0/develop/authentication-data-api/">
     *                           Authentication Data API</a>
     */
    public static String fetchSensitiveData(String sessionDataKey) throws FinancialServicesException {
        try {
            // Need to make SCHEME:HOST:PORT dynamic
            URL requestUrl = new URL("https://localhost:9446" + API_ENDPOINT + sessionDataKey);
            HttpURLConnection connection = (HttpURLConnection) requestUrl.openConnection();

            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept", "application/json");

            StringBuilder response = new StringBuilder();

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) { // 200
                BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();

            } else {
                log.error("Sensitive data retrieval from Identity Server failed with HTTP response: " +
                        responseCode);
                throw new FinancialServicesException("Failed to fetch sensitive data from Identity Server.");
            }
            connection.disconnect();

            return response.toString();

        } catch (Exception e) {
            log.error("Sensitive data retrieval from Identity Server failed.");
            throw new FinancialServicesException("Failed to fetch sensitive data from Identity Server.");
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
    public static ConcurrentMap<String, String[]> extractQueryParams(String query) throws UnsupportedEncodingException {
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
}
