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

import android.app.PendingIntent;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;

import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.AuthorizationServiceDiscovery;
import net.openid.appauth.TokenRequest;
import net.openid.appauth.TokenResponse;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

public class OktaAppAuth extends AppCompatActivity {

    public static final String TAG = "OktaAppAuth";
    public static Boolean revoked = false;

    // Configuration Object
    OktaConfiguration configuration = new OktaConfiguration();

    public static final String SCOPE = "openid profile email address phone groups offline_access gravatar";
    private static final String KEY_USER_INFO = "userInfo";
    private static final String EXTRA_AUTH_SERVICE_DISCOVERY = "authServiceDiscovery";
    private static final String EXTRA_AUTH_STATE = "authState";

    private AuthState mAuthState = null;
    private AuthorizationService mAuthService;
    private JSONObject mUserInfoJson;

    /**
     * Starts the main AppAuth Standard Authentication Flow
     *
     * @param savedInstanceState: Bundle of existing values
     */

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_okta_app_auth);

        mAuthService = new AuthorizationService(this);

        if (savedInstanceState != null) {
            if (savedInstanceState.containsKey(configuration.kAppAuthExampleAuthStateKey)) {
                try {
                    if (savedInstanceState.getString(configuration.kAppAuthExampleAuthStateKey) != null) {
                        Log.d(TAG, "Grabbing authState from savedInstance");
                        mAuthState = AuthState.fromJson(savedInstanceState.
                                getString(configuration.kAppAuthExampleAuthStateKey));
                    }
                } catch (JSONException e) {
                    Log.e(TAG, "Malformed authorization JSON saved", e);
                }
            }
            if (savedInstanceState.containsKey(KEY_USER_INFO)) {
                try {
                    Log.d(TAG, "Grabbing userInfo from savedInstance");
                    mUserInfoJson = new JSONObject(savedInstanceState.getString(KEY_USER_INFO));
                } catch (JSONException e) {
                    Log.e(TAG, "Failed to parse saved user info JSON", e);
                }
            }
        }

        Intent intent = getIntent();
        if (intent != null) {
            if (mAuthState == null) {
                AuthorizationResponse response = AuthorizationResponse.fromIntent(getIntent());
                AuthorizationException exception = AuthorizationException.fromIntent(getIntent());

                // Check for creation, if not - create
                if (response != null || exception != null) {
                    mAuthState = new AuthState(response, exception);
                }
                if (response != null) {
                    Log.d(TAG, "Received AuthorizationResponse");
                    exchangeAuthorizationCode(response);
                } else {
                    Log.d(TAG, "Authorization failed: " + exception);
                }
            }
        }
    }

    /**
     * Get method for retrieving current authState
     *
     * @return mAuthState
     */
    public AuthState getAuthState(){
        return mAuthState;
    }

    /**
     * Performs Authorization code exchange
     */
    private void exchangeAuthorizationCode(AuthorizationResponse authorizationResponse) {
        performTokenRequest(authorizationResponse.createTokenExchangeRequest());
    }

    /**
     * Sends request for Token
     */
    private void performTokenRequest(TokenRequest request) {
        mAuthService.performTokenRequest(
                request,
                new AuthorizationService.TokenResponseCallback() {
                    @Override
                    public void onTokenRequestCompleted(
                            @Nullable TokenResponse tokenResponse,
                            @Nullable AuthorizationException ex) {
                        receivedTokenResponse(tokenResponse, ex);
                    }
                });
    }

    /**
     * Sets display text for token value
     *
     */
    private void receivedTokenResponse(
            @Nullable TokenResponse tokenResponse,
            @Nullable AuthorizationException authException) {
        Log.d(TAG, "Token request complete");
        mAuthState.update(tokenResponse, authException);
        Log.d(TAG, "Access Token: \n" + mAuthState.getAccessToken()
                + "\n\nID Token: \n" + mAuthState.getIdToken()
                + "\n\nRefresh Token: \n" + mAuthState.getRefreshToken());
        createAlert("Tokens", "Check logs for token values");
    }

    /**
     * Starts webView intent
     *
     */
    static PendingIntent createPostAuthorizationIntent(
            @NonNull Context context,
            @NonNull AuthorizationRequest request,
            @Nullable AuthorizationServiceDiscovery discoveryDoc
            ) {
        Intent intent = new Intent(context, OktaAppAuth.class);
        intent.putExtra(EXTRA_AUTH_STATE, discoveryDoc.docJson.toString());
        if (discoveryDoc != null) {
            intent.putExtra(EXTRA_AUTH_SERVICE_DISCOVERY, discoveryDoc.docJson.toString());
        }

        return PendingIntent.getActivity(context, request.hashCode(), intent, 0);
    }

    /**
     * Gets endpoints from configured domain
     *
     * @param intent: Browser intent
     * @return
     */
    static AuthorizationServiceDiscovery getDiscoveryDocFromIntent(Intent intent) {
        if (!intent.hasExtra(EXTRA_AUTH_SERVICE_DISCOVERY)) {
            return null;
        }
        String discoveryJson = intent.getStringExtra(EXTRA_AUTH_SERVICE_DISCOVERY);
        try {
            return new AuthorizationServiceDiscovery(new JSONObject(discoveryJson));
        } catch (JSONException | AuthorizationServiceDiscovery.MissingArgumentException  ex) {
            throw new IllegalStateException("Malformed JSON in discovery doc");
        }
    }

    /**
     * Sends authorization request to authorization endpoint
     *
     * @param view: UIButton 'Get Tokens'
     */
    public void sendAuthorizationRequest(View view) {
        final AuthorizationServiceConfiguration.RetrieveConfigurationCallback retrieveCallback =
                new AuthorizationServiceConfiguration.RetrieveConfigurationCallback() {
                    @Override
                    public void onFetchConfigurationCompleted(
                            @Nullable AuthorizationServiceConfiguration authorizationServiceConfiguration,
                            @Nullable AuthorizationException e) {
                        if(e != null) {
                            Log.w(TAG, "Failed to retrieve configuration for " + configuration.kIssuer, e);
                        } else {
                            Log.d(TAG, "Configuration retrieved for " + configuration.kIssuer + ", proceeding");
                            makeAuthRequest(authorizationServiceConfiguration);
                        }
                    }
                };
        String discoveryEndpoint = configuration.kIssuer + "/.well-known/openid-configuration";
        AuthorizationServiceConfiguration.fetchFromUrl(Uri.parse(discoveryEndpoint), retrieveCallback);
    }

    /**
     * Makes authentication request to endpoints in discovery document
     *
     * @param authorizationServiceConfiguration: AppAuth authorizationService detail
     */
    private void makeAuthRequest(
            @NonNull AuthorizationServiceConfiguration authorizationServiceConfiguration
            ) {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest.Builder(
                authorizationServiceConfiguration,
                configuration.kClientID,
                AuthorizationRequest.RESPONSE_TYPE_CODE,
                Uri.parse(configuration.kRedirectURI)).setScope(SCOPE).build();
        Log.d(TAG, "Making auth request to " + authorizationServiceConfiguration.authorizationEndpoint);
        mAuthService.performAuthorizationRequest(
                authorizationRequest,
                createPostAuthorizationIntent(
                        this.getApplicationContext(),
                        authorizationRequest,
                        authorizationServiceConfiguration.discoveryDoc
                        ));

    }

    /**
     * Calls userinfo endpoint through AsyncTask
     */
    class RequestTask extends AsyncTask<Void, Void, Void> {
        AuthState mAuthState = getAuthState();

        @Override
        protected Void doInBackground(Void... params) {
            try {
                String token = mAuthState.getAccessToken();
                if (!revoked) {
                    mAuthState.performActionWithFreshTokens(mAuthService, new AuthState.AuthStateAction() {
                        @Override
                        public void execute(String accessToken, String idToken, AuthorizationException ex) {
                            if (ex != null) {
                                Log.d(TAG, "Token refresh failed when fetching user info");
                                return;
                            }
                            performRequest(accessToken);
                        }
                    });
                } else { performRequest(token); }
            } catch (Exception e) {
                Log.e(TAG, "Failed to establish connection.", e.fillInStackTrace());
            }
            return null;
        }
    }
    /**
     *  Performs HTTP Request with access token
     *
     */
    public void performRequest(String token){
        if (mAuthState.getAuthorizationServiceConfiguration() == null) {
            Log.d(TAG, "Cannot make userInfo request without service configuration");
        }

        AuthorizationServiceDiscovery discoveryDoc = getDiscoveryDocFromIntent(getIntent());
        if (discoveryDoc == null) {
            throw new IllegalStateException("no available discovery doc");
        }

        URL userInfoEndpoint = null;

        try { userInfoEndpoint = new URL(discoveryDoc.getUserinfoEndpoint().toString()); }
        catch (MalformedURLException urlEx) { Log.e(TAG, "Failed to construct user info endpoint URL", urlEx); }

        InputStream userInfoResponse = null;

        try {
            HttpURLConnection conn = (HttpURLConnection) userInfoEndpoint.openConnection();
            conn.setRequestProperty("Authorization", "Bearer " + token);
            conn.setInstanceFollowRedirects(false);

            if(conn.getResponseCode() == 401) {
                Log.e(TAG, "Access Token Invalid");
                updateUserInfo(new JSONObject(("{'invalid_token' : 'The access token is invalid'}")));
            }

            userInfoResponse = conn.getInputStream();
            String response = readStream(userInfoResponse);
            updateUserInfo(new JSONObject(response));

        } catch (IOException ioEx) {
            Log.e(TAG, "Network error when querying userinfo endpoint", ioEx);
            System.out.println("Err: " + ioEx.getMessage());
        } catch (JSONException jsonEx) {
            Log.e(TAG, "Failed to parse userinfo response");
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        } finally {
            if (userInfoResponse != null) {
                try {
                    userInfoResponse.close();
                } catch (IOException ioEx) {
                    Log.e(TAG, "Failed to close userinfo response stream", ioEx);
                }
            }
        }

    }

    /**
     * Starts async task for calling /userinfo endpoint from display
     *
     * @param view: UIButton 'Get User Info'
     */
    public void fetchUserInfo(View view) {
        if (mAuthState != null) {
            RequestTask requestTask = new RequestTask();
            if (Build.VERSION.SDK_INT >=Build.VERSION_CODES.HONEYCOMB){
                requestTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
            } else { requestTask.execute(); }
        } else {
            Log.d(TAG, "Not authenticated");
            createAlert("Error", "Not authenticated");
        }

    }

    /**
     * Updates User ID information on display
     *
     * @param jsonObject: Response JSON
     */
    private void updateUserInfo(final JSONObject jsonObject) {
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            @Override
            public void run() {
                mUserInfoJson = jsonObject;
                Log.d(TAG, jsonObject.toString());
                createAlert("User Info", jsonObject.toString()
                        .replace("\\/","/")
                        .replace(",", ",\n  ")
                        .replace("{", "{\n  ")
                        .replace("}", "}\n  "));
            }
        });
    }

    /**
     * Reads input into the buffer
     *
     * @param stream: HTTP response stream
     * @return String
     * @throws IOException
     */
    public static String readStream(InputStream stream) throws IOException {
        int BUFFER_SIZE = 1024;

        BufferedReader br = new BufferedReader(new InputStreamReader(stream));
        char[] buffer = new char[BUFFER_SIZE];
        StringBuilder sb = new StringBuilder();
        int readCount;
        while((readCount = br.read(buffer)) != -1) {
            sb.append(buffer, 0, readCount);
        }
        return sb.toString();
    }

    /**
     * Creates UI Alert given Title and Message
     *
     * @param title: Title of alert
     * @param message: Message body of alert
     */
    public void createAlert(String title, String message) {
        AlertDialog.Builder alert = new AlertDialog.Builder(this);
        alert.setTitle(title);
        alert.setMessage(message);
        alert.setCancelable(true);

        alert.setNegativeButton(
                "OK",
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
                        dialog.cancel();
                    }
                });

        AlertDialog dialog = alert.create();
        dialog.show();
    }

    /**
     * Refreshes access and id token with refresh token
     *
     * @param view: UIButton 'Refresh Token'
     */
    public void refreshTokens(View view) {
        if (mAuthState != null) {
            performTokenRequest(mAuthState.createTokenRefreshRequest());
            Log.d(TAG, "Refreshed Access Token");
        } else {
            createAlert("Error", "Not authenticated");
            Log.d(TAG, "Not authenticated"); }
    }

    /**
     * Revokes current access token
     *
     * @param view: UIButton 'Revoke Token'
     */
    public void revokeTokens(View view){
        if (mAuthState != null) {
            Log.d(TAG, "Revoking Tokens");

            // Call revoke endpoint to terminate access_token
            AsyncTask revokeTask = new AsyncTask() {
                @Override
                protected Object doInBackground(Object[] objects) {
                    callRevokeEndpoint();
                    return null;
                }

                @Override
                protected void onPostExecute(Object result) {
                    mAuthState.setNeedsTokenRefresh(true);
                    createAlert("Success", "Tokens revoked");
                    revoked = true;
                }

                ;
            };

            if (Build.VERSION.SDK_INT >=Build.VERSION_CODES.HONEYCOMB){
                revokeTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
            } else {
                revokeTask.execute(); }

        } else {
            createAlert("Error", "Not authenticated");
            Log.d(TAG, "Not authenticated");
        }
    }

    public void callRevokeEndpoint() {
        try {
            if (mAuthState.getAuthorizationServiceConfiguration() == null) {
                Log.d(TAG, "Cannot make request without service configuration");
            }

            AuthorizationServiceDiscovery discoveryDoc = getDiscoveryDocFromIntent(getIntent());
            if (discoveryDoc == null) { throw new IllegalStateException("no available discovery doc"); }

            try {
                URL url = new URL(discoveryDoc.getIssuer() + "/oauth2/v1/revoke");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                String params = "client_id=" + configuration.kClientID + "&token=" + mAuthState.getAccessToken();
                byte[] postParams = params.getBytes("UTF-8");
                conn.setRequestMethod("POST");
                conn.setInstanceFollowRedirects(false);
                conn.setDoOutput(true);
                conn.connect();
                conn.getOutputStream().write(postParams);
                if (conn.getResponseCode() == 200 || conn.getResponseCode() == 204) {
                    Log.d(TAG, "Previous access token is considered invalid");
                    mAuthState.setNeedsTokenRefresh(true);

                } else {
                    Log.e(TAG, "Unable to revoke access token");
                }

            } catch (Exception e) {
                Log.e("Error", e.getMessage());
            }

        } catch (Exception e) {
            Log.e(TAG, "Failed to establish connection.", e.fillInStackTrace());
        }
    }

    /**
     * Removes all tokens from current AuthState
     *
     * @param view
     */
    public void clearTokens(View view){
        if(mAuthState != null) {
            mAuthState = null;
            createAlert("Success", "All forgot all tokens");
        } else {
            createAlert("Error", "Not authenticated");
            Log.d(TAG, "Not authenticated");
        }
    }

    /**
     * Launches new activity for testing API
     * @param view
     */
    public void exampleApi(View view) {
        if (mAuthState != null) {
            Intent intent = new Intent(this, DisplayImageActivity.class);
            intent.putExtra("apiEndpoint", configuration.apiEndpoint);
            intent.putExtra("accessToken", mAuthState.getAccessToken());
            startActivity(intent);
        } else { createAlert("Error", "Not authenticated"); };

    }

    /**
     * Saves authState and userInfo JSON for recreating activity
     *
     * @param state
     */
    @Override
    protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        if (mAuthState != null) {
            state.putString(configuration.kAppAuthExampleAuthStateKey, mAuthState.toJsonString());
        }
        if (mUserInfoJson != null) {
            state.putString(KEY_USER_INFO, mUserInfoJson.toString());
        }
    }

    /**
     *  Dispose of unused resources
     */
    @Override
    protected void onDestroy(){
        super.onDestroy();
        mAuthService.dispose();
    }
}

