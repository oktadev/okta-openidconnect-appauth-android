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

import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Activity showcasing Android AppAuth and server communication
 */
public class DisplayImageActivity extends AppCompatActivity {
    String apiEndpointURL;
    String accessToken;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_display_image);

        Button returnButton = (Button) findViewById(R.id.returnButton);
        returnButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                finish();
            }
        });

        Intent intentExtras = getIntent();
        apiEndpointURL = intentExtras.getStringExtra("apiEndpoint");
        accessToken = intentExtras.getStringExtra("accessToken");

        GetImageUrl userImageUrl = new GetImageUrl();
        userImageUrl.execute(apiEndpointURL);

    }

    /**
     * Performs async task to retrieve image from server
     */
    protected class GetImageUrl extends AsyncTask<String, String, JSONObject> {
        @Override
        protected JSONObject doInBackground(String... urls) {
            URL url= null;
            JSONObject response = null;

            try { url = new URL(urls[0]); }
            catch (Exception e) { Log.e("Error", e.getMessage()); }

            try {
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestProperty("Authorization", "Bearer " + accessToken);
                conn.setRequestMethod("GET");
                conn.setInstanceFollowRedirects(false);
                String responseString = readStream(conn.getInputStream());
                response = new JSONObject(responseString);
                conn.disconnect();
            } catch (Exception e) { Log.e("Error", e.getMessage()); }

            return response;
        }

        /**
         * Outputs error or success response in ImageView and/or textView
         *
         * @param response: JSONObject from HTTP response
         */
        protected void onPostExecute(JSONObject response) {
            if (response != null) {
                System.out.print(response);
                TextView userName = (TextView) findViewById(R.id.nameView);
                if (response.has("Error")) {
                    userName.setText(response.optString("Error"));
                    findViewById(R.id.loadingPanel).setVisibility(View.GONE);
                } else {
                    String name = response.optString("name");
                    String imageURL = response.optString("image");

                    try {
                        DownloadImageTask downloadImageTask = new DownloadImageTask();
                        downloadImageTask.execute(imageURL);
                        userName.setText(name);
                        findViewById(R.id.loadingPanel).setVisibility(View.GONE);
                    } catch (Exception e) { Log.e("Error", e.getMessage()); }
                }

            } else { finish(); }
        }
    }

    /**
     * AsyncTask to download image from URL
     */
    private class DownloadImageTask extends AsyncTask<String, Void, Bitmap> {

        @Override
        protected Bitmap doInBackground(String... urls) {
            URL url= null;
            Bitmap response = null;

            try { url = new URL(urls[0]); }
            catch (Exception e) { Log.e("Error", e.getMessage()); }

            try { response = BitmapFactory.decodeStream(url.openConnection().getInputStream()); }
            catch (Exception e) { Log.e("Error", e.getMessage()); }

            return response;
        }

        /**
         * Populates imageView with image from URL
         * @param response: Bitmap of image
         */
        protected void onPostExecute(Bitmap response) {
            if (response != null) {
                try {
                    ImageView imageView = (ImageView) findViewById(R.id.imageView);
                    imageView.setImageBitmap(response);
                    findViewById(R.id.loadingPanel).setVisibility(View.GONE);

                } catch (Exception e) { Log.e("Error", e.getMessage()); }
            } else { finish(); }
        }
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
}
