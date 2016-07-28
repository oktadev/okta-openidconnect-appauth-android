# Android Native Application with AppAuth
Sample application for communicating with OAuth 2.0 and OpenID Connect providers. Demonstrates single-sign-on (SSO) with [AppAuth for Android](https://github.com/openid/AppAuth-Android).

## Running the Sample with your Okta Organization

###Pre-requisites
This sample application was tested with an Okta org. If you do not have an Okta org, you can easily [sign up for a free Developer Okta org](https://www.okta.com/developer/signup/).

1. Verify OpenID Connect is enabled for your Okta organization. `Admin -> Applications -> Add Application -> Create New App -> OpenID Connect`
  - If you do not see this option, email [developers@okta.com](mailto:developers@okta.com) to enable it.
2. In the **Create A New Application Integration** screen, click the **Platform** dropdown and select **Native app only**
3. Press **Create**. When the page appears, enter an **Application Name**. Press **Next**.
4. Add the reverse DNS notation of your organization to the *Redirect URIs*, followed by a custom route. *(Ex: "com.oktapreview.example:/oauth")*
5. Click **Finish** to redirect back to the *General Settings* of your application.
6. Select the **Edit** button in the *General Settings* section to configure the **Allowed Grant Types**
  - Ensure *Authorization Code* and *Refresh Token* are selected in **Allowed Grant Types**
  - **Save** the application
7. In the *Client Credentials* section verify *Proof Key for Code Exchange (PKCE)* is the default **Client Authentication**
8. Copy the **Client ID**, as it will be needed for the `OktaConfiguration.java` configuration file.
9. Finally, select the **People** tab and **Assign to People** in your organization.

### Configure the Sample Application
Once the project is cloned, simply open the project in [Android Studio](https://developer.android.com/studio/index.html) and `Import` the project.

Update the **kIssuer**, **kClientID**, and **kRedirectURI** in your `OktaConfiguration.java` file:
```java
// OktaConfiguration.java

public class OktaConfiguration {
    public String kIssuer = "https://example.oktapreview.com";        // Base url of Okta Developer domain
    public String kClientID = "79arVRKBcBEYMuMOXrYF";                 // Client ID of Application
    public String kRedirectURI = "com.oktapreview.example:/oauth";    // Reverse DNS notation of base url with oauth route
    public String kAppAuthExampleAuthStateKey = "com.okta.oauth.authState";
    public String apiEndpoint = "https://example.server.com";
}
```

Update the `redirectURL` located in `app/res/values/strings.xml` to reverse DNS notation of the **base url**:
```xml
...
<string name="redirectURL">com.oktapreview.example</string>
```

Update the **global** variable `SCOPE` to the desired values. Separate values by a **single** space.
```java
//OktaAppAuth.java

public static final String SCOPE = "openid profile email address phone groups offline_access";
```

## Running the Sample Application

| Get Tokens      | Get User Info  | Refresh Token  | Revoke Token   | Call API       | Clear Tokens   |
| :-------------: |:-------------: |:-------------: |:-------------: |:-------------: |:-------------: |
| ![Get Tokens](https://raw.githubusercontent.com/jmelberg/okta-openidconnect-appauth-sample-swift/master/OpenIDConnectSwift/Assets.xcassets/key_circle.imageset/key.png)| ![Get User Info](https://raw.githubusercontent.com/jmelberg/okta-openidconnect-appauth-sample-swift/master/OpenIDConnectSwift/Assets.xcassets/Reporting.imageset/Reporting.png)| ![Refresh Token](https://raw.githubusercontent.com/jmelberg/okta-openidconnect-appauth-sample-swift/master/OpenIDConnectSwift/Assets.xcassets/refresh.imageset/api_call.png)| ![Revoke Token](https://raw.githubusercontent.com/jmelberg/okta-openidconnect-appauth-sample-swift/master/OpenIDConnectSwift/Assets.xcassets/revoke.imageset/revoke.png) | ![Call API](https://raw.githubusercontent.com/jmelberg/okta-openidconnect-appauth-sample-swift/master/OpenIDConnectSwift/Assets.xcassets/refresh.imageset/api_call.png) | ![Clear Tokens](https://raw.githubusercontent.com/jmelberg/okta-openidconnect-appauth-sample-swift/master/OpenIDConnectSwift/Assets.xcassets/ic_key.imageset/MFA_for_Your_Apps.png)|

###Get Tokens

Interacts with the Okta Authorization Server by using the discovered values from the organization's `https://example.oktapreview.com/.well-known/openid-configuration` endpoint. If the endpoint is found, the method `makeAuthRequest` generates the request by passing in the required scopes and opening up an in-app browser.

```java
// OktaAppAuth.java

private void makeAuthRequest(
  @NonNull AuthorizationServiceConfiguration authorizationServiceConfiguration) {
    AuthorizationRequest authorizationRequest = new AuthorizationRequest.Builder(
      authorizationServiceConfiguration,
      configuration.kClientID,
      AuthorizationRequest.RESPONSE_TYPE_CODE,
      Uri.parse(configuration.kRedirectURI)).setScope(SCOPE).build();

    mAuthService.performAuthorizationRequest(
      authorizationRequest,
      createPostAuthorizationIntent(
      this.getApplicationContext(),
      authorizationRequest,
      authorizationServiceConfiguration.discoveryDoc
    ));
  }

  
```
If authenticated, the mobile app receives an `idToken`, `accessToken`, and `refreshToken` which are available in the Android Monitor area.

###Get User Info
If the user is authenticated, calling the [`/userinfo`](http://developer.okta.com/docs/api/resources/oidc#get-user-information) endpoint will retrieve user data. If received, the output is printed to the Debug area and a UIAlert.

**NOTE:** Before calling the `/userinfo` endpoint, the `accessToken` is refreshed by AppAuth's `performActionWithFreshTokens()` method. However, if the `accessToken` was previously **revoked**, the token will **not** be refreshed.

```java
// OktaAppAuth.java

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
              // Error
            }
            performRequest(accessToken);
          }
        });
      } else {
        performRequest(token);
      }
    } catch (Exception e) {
        // Exception
    }
    return null;
  }
}
```

###Refresh Tokens
The AppAuth methods `performTokenRequest` and `createTokenRefreshRequest()` are used to refresh the current **access token** if the user is authenticated.

```java
// OktaAppAuth.java

public void refreshTokens(View view) {
  if (mAuthState != null) {
    performTokenRequest(mAuthState.createTokenRefreshRequest());
  } else {
    Log.d(TAG, "Not authenticated"); }
}
```

###Revoke Tokens
If authenticated, the current `accessToken` is passed to the `/revoke` endpoint to be revoked.

```java
// OktaAppAuth.java

public void callRevokeEndpoint() {
  ...
  try {
    URL url = new URL(discoveryDoc.getIssuer() + "/oauth2/v1/revoke");
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    String params = "client_id=" + configuration.kClientID + "&token="+mAuthState.getAccessToken();
    byte[] postParams = params.getBytes("UTF-8");
    conn.setRequestMethod("POST");
    conn.setInstanceFollowRedirects(false);
    conn.setDoOutput(true);
    conn.connect();
    conn.getOutputStream().write(postParams);
    if (conn.getResponseCode() == 200 || conn.getResponseCode() == 204) {
      mAuthState.setNeedsTokenRefresh(true);
    }
  }
  catch (Exception e) {
    // Exception
  }
} 
```

###Call API
Passes the current access token *(fresh or revoked)* to a resource server for validation. Returns an api-specific details about the authenticated user.

Currently, the [resource server](https://github.com/jmelberg/oauth-resource-server) is implemented with [node.js](https://nodejs.org/en/) and returns an image from [Gravatar API](https://en.gravatar.com/site/implement/). Please review the [setup information in the Resource Server README](https://github.com/jmelberg/oauth-resource-server/blob/master/README.md) for proper configuration.

> Example Response

```java
// DisplayImageActivity.java

{
  image = "www.gravatar.com/avatar/<hash>?s=200&r=x&d=retro";
  name = "example@okta.com";
}
```


###Clear Tokens
Sets the current `authState` to `nil` - clearing all tokens from AppAuth's cache.
