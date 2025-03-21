/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 * <p>
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 *     http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.financial.services.accelerator.consent.mgt.extensions.validate.model;

import org.json.JSONObject;
import org.wso2.financial.services.accelerator.common.extension.model.Request;

import java.util.Map;

/**
 * Consent validate request model.
 */
public class ConsentValidateRequest extends Request {
    JSONObject consentPayload;
    String consentId;
    JSONObject dataPayload;

    public ConsentValidateRequest(String consentId, JSONObject consentPayload, JSONObject dataPayload,
                                  Map<String, String> additionalParams) {
        super(null, additionalParams);
        this.consentPayload = consentPayload;
        this.consentId = consentId;
        this.dataPayload = dataPayload;
    }

    public JSONObject getConsentPayload() {
        return consentPayload;
    }

    public void setConsentPayload(JSONObject consentPayload) {
        this.consentPayload = consentPayload;
    }

    public String getConsentId() {
        return consentId;
    }

    public void setConsentId(String consentId) {
        this.consentId = consentId;
    }

    public JSONObject getDataPayload() {
        return dataPayload;
    }

    public void setDataPayload(JSONObject dataPayload) {
        this.dataPayload = dataPayload;
    }

}
