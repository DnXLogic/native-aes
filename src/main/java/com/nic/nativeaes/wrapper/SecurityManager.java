package com.nic.nativeaes.wrapper;

import android.content.Context;

import com.nic.controller.APIController;

/**
 * Created by Deepak on 13-Oct-17.
 */
@SuppressWarnings("JniMissingFunction")
public class SecurityManager {
    public static final String ENCODING = "UTF-8";
    public static final int ENCRYPT = 0;
    public static final int DECRYPT = 1;

    public static final String HTTP_GET = "G";
    public static final String HTTP_POST = "P";
    public static final String ENABLE_SSL = "Y";
    public static final String DISABLE_SSL = "N";

    public static SecurityManager instance;
    private static Context context;
    private static Object apiHelper;
    private static Object apiController;

    static {
        System.loadLibrary("native-aes");
    }

    private SecurityManager() {
    }

    public static SecurityManager getInstance(Context context, Object apiHelper) {
        SecurityManager.context = context;
        SecurityManager.apiHelper = apiHelper;
        SecurityManager.apiController = APIController.getInstance();
        if (instance == null) {
            instance = new SecurityManager();
        }
        return instance;
    }

    private static Context getClientContext() {
        return context;
    }

    private static Object getClientHelper() {
        return apiHelper;
    }

    private static Object getApiController() {
        return apiController;
    }


    public byte[] processData(byte[] data, long timestamp, int mode) {
        return aesProcessing(data, timestamp, mode);
    }

    public String processInput(byte[] data, long timestamp, String loc, String methodType, String sslMode) {
        return processRequest(data, timestamp, loc, methodType, sslMode);
    }

    private native byte[] aesProcessing(byte[] data, long time, int mode);

    private native String processRequest(byte[] data, long time, String loc, String methodType, String sslMode);

}
