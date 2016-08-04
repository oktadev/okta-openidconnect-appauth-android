/* Author: Jordan Melberg */
/*!
 * Copyright (c) 2016, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

package jmelberg.okta.com.openidconnectandroid;

/**
 * Configuration class
 */

public class OktaConfiguration {
    public String kIssuer = "https://example.oktapreview.com";        // Base url of Okta Developer domain
    public String kClientID = "79arVRKBcBEYMuMOXrYF";                 // Client ID of Application
    public String kRedirectURI = "com.oktapreview.example:/oauth";    // Reverse DNS notation of base url with oauth route
    public String kAppAuthExampleAuthStateKey = "com.okta.oauth.authState";
    public String apiEndpoint = "https://a332ae16.ngrok.io/protected";

    public OktaConfiguration() {}

}
