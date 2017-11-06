#include <stdio.h>
#include <jni.h>
#include <stdlib.h>
#include <android/log.h>

#include <stdlib.h> /* exit */
#include <unistd.h> /* read, write, close */
#include <string.h> /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h> /* struct hostent, gethostbyname */
#include "aes/aes.h"

//CRYPT CONFIG
#define MAX_LEN (2*1024*1024)
#define ENCRYPT 0
#define DECRYPT 1
#define ENCODE 0
#define DECODE 1
#define AES_KEY_SIZE 256
#define READ_LEN 10


#define  LOG_TAG    "TEST"

#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)
#define  LOGW(...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG,__VA_ARGS__)
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)
#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)

// Method Declarations

jstring byteToString(JNIEnv *jniEnv, jobject obz, jbyteArray data);

jbyteArray stringToByte(JNIEnv *jniEnv, jobject obz, jstring data);

jstring concat(JNIEnv *env, jobject obz, jstring str1, jstring str2);

// Not Tested
char *jstringToChar(JNIEnv *env, jstring jstr) {
    char *rtn = NULL;
    jclass cls = (*env)->FindClass(env, "java/lang/String");
    jstring encoding = (*env)->NewStringUTF(env, "utf-8");
    jmethodID mid = (*env)->GetMethodID(env, cls, "getBytes", "(Ljava/lang/String;)[B");
    jbyteArray barr = (jbyteArray) (*env)->CallObjectMethod(env, jstr, mid, encoding);
    jsize alen = (*env)->GetArrayLength(env, barr);
    jbyte *ba = (*env)->GetByteArrayElements(env, barr, JNI_FALSE);
    if (alen > 0) {
        rtn = (char *) malloc(alen + 1);
        memcpy(rtn, ba, alen);
        rtn[alen] = 0;
    }
    (*env)->ReleaseByteArrayElements(env, barr, ba, 0);
    return rtn;
}
// Not Tested
/*jstring jbyteArrayTojstring(JNIEnv *env, jbyteArray jbyteArray1) {
    char *result = NULL;
    jsize alen = (*env)->GetArrayLength(env, jbyteArray1);
    jbyte *bytes = (*env)->GetByteArrayElements(env, jbyteArray1, JNI_FALSE);
    if (alen > 0) {
        result = (char *) malloc(alen + 1);
        memcpy(result, bytes, alen);
        result[alen] = 0;
    }
    (*env)->ReleaseByteArrayElements(env, jbyteArray1, bytes, 0);
    return (*env)->NewStringUTF(env, result);
}*/
// Not Tested
/*jstring charTojstring(JNIEnv *env, const char *input) {
    jclass cls = (*env)->FindClass(env, "java/lang/String;");
    jmethodID mid = (*env)->GetMethodID(env, cls, "<init>", "([BLjava/lang/String;)V");
    jbyteArray bytes = (*env)->NewByteArray(env, strlen(input));
    (*env)->SetByteArrayRegion(env, bytes, 0, strlen(input), (jbyte *) input);
    jstring encoding = (*env)->NewStringUTF(env, "utf-8");
    return (jstring) (*env)->NewObject(env, cls, mid, bytes, encoding);
}*/

jstring jbyteArrayTojstring(JNIEnv *env, jbyteArray bytes) {
    jclass cls = (*env)->FindClass(env, "java/lang/String;");
    jmethodID mid = (*env)->GetMethodID(env, cls, "<init>", "([BLjava/lang/String;)V");
    //jbyteArray bytes = (*env)->NewByteArray(env, strlen(input));
    //(*env)->SetByteArrayRegion(env, bytes, 0, strlen(input), (jbyte *) input);
    jstring encoding = (*env)->NewStringUTF(env, "utf-8");
    return (jstring) (*env)->NewObject(env, cls, mid, bytes, encoding);
}

jbyteArray jstringTojbyteArray(JNIEnv *env, jstring jstr) {
    jclass cls = (*env)->FindClass(env, "java/lang/String");
    jstring encoding = (*env)->NewStringUTF(env, "utf-8");
    jmethodID mid = (*env)->GetMethodID(env, cls, "getBytes", "(Ljava/lang/String;)[B");
    return (jbyteArray) (*env)->CallObjectMethod(env, jstr, mid, encoding);
}

jstring getVal(JNIEnv *env, jobject obj, jstring str1, jstring str2) {
    //Password 16 digits in str1
    //Password 12 digits in str2
    // Add Fixed 4 digit to get Final "!123"
    char *temp1 = NULL;
    char *temp2 = NULL;
    jbyteArray jbyteArray1 = jstringTojbyteArray(env, str1);
    jbyteArray jbyteArray2 = jstringTojbyteArray(env, str2);
    jsize size1 = (*env)->GetArrayLength(env, jbyteArray1);
    jsize size2 = (*env)->GetArrayLength(env, jbyteArray2);
    jbyte *bytes1 = (*env)->GetByteArrayElements(env, jbyteArray1, 0);
    if (size1 > 0) {
        for (int i = 0; i < size1; i++) {
            bytes1[i] = bytes1[i] + 1;
        }
        temp1 = (char *) malloc(size1 + 1);
        memcpy(temp1, bytes1, size1);
        temp1[size1] = 0;
    }
    (*env)->ReleaseByteArrayElements(env, jbyteArray1, bytes1, 0);
    //LOGD("TEMP 1 =%s", temp1);

    jbyte *bytes2 = (*env)->GetByteArrayElements(env, jbyteArray2, 0);
    if (size2 > 0) {
        for (int i = 0; i < size2; i++) {
            bytes2[i] = bytes2[i] + 1;
        }
        temp2 = (char *) malloc(size2 + 1);
        memcpy(temp2, bytes2, size2);
        temp2[size2] = 0;
    }
    (*env)->ReleaseByteArrayElements(env, jbyteArray2, bytes2, 0);
    //LOGD("TEMP 2 =%s", temp2);

    jstring tempStr = concat(env, obj, (*env)->NewStringUTF(env, temp1),
                             (*env)->NewStringUTF(env, temp2));
    //LOGD("TEMPSTR =%s", (*env)->GetStringUTFChars(env, tempStr, 0));
    jstring result = concat(env, obj, tempStr, (*env)->NewStringUTF(env, "!@#$"));
    //LOGD("RESULT =%s", (*env)->GetStringUTFChars(env, result, 0));
    return result;

    /*const char *input1 = (*env)->GetStringUTFChars(env, str1, 0);
    unsigned char *temp1 = (unsigned char *) malloc(16);
    int i;
    for (i = 0; i < 16; i++) {
        temp1[i] = (unsigned char) ((int) input1[i] + 1);
    }
    LOGD("TEMP 1 =%s", temp1);

    const char *input2 = (*env)->GetStringUTFChars(env, str2, 0);
    unsigned char *temp2 = (unsigned char *) malloc(12);
    int j;
    for (j = 0; j < 12; j++) {
        temp2[j] = (unsigned char) ((int) input2[j] + 1);
    }
    LOGD("TEMP 2 =%s", temp2);

    jstring temp = concat(env, obj, (*env)->NewStringUTF(env, temp1),
                          (*env)->NewStringUTF(env, temp2));

    jstring result=concat(env, obj, temp, (*env)->NewStringUTF(env, "!@#$"));

    LOGD("TEMP =%s", (*env)->GetStringUTFChars(env, (jstring)result, 0));

    (*env)->ReleaseStringUTFChars(env, str1, input1);
    (*env)->ReleaseStringUTFChars(env, str2, input2);

    return result;*/
}

jbyteArray encodeDecodeBase64(JNIEnv *jniEnv, jobject obz, jbyteArray data, jint mode) {

    jclass cls = (*jniEnv)->FindClass(jniEnv,
                                      "android/org/apache/commons/codec/binary/Base64");
    if (cls != NULL) {
        jmethodID mid = NULL;
        if (mode == ENCODE) { //encodeBase64
            mid = (*jniEnv)->GetStaticMethodID(jniEnv, cls, "encodeBase64",
                                               "([B)[B");
        } else if (mode == DECODE) { //decodeBase64
            mid = (*jniEnv)->GetStaticMethodID(jniEnv, cls, "decodeBase64",
                                               "([B)[B");
        }

        if (mid == NULL) return NULL;
        return (jbyteArray) (*jniEnv)->CallStaticObjectMethod(jniEnv, cls, mid,
                                                              data);
    }
}

jbyteArray stringToByte(JNIEnv *jniEnv, jobject obz, jstring data) {
    jclass cls = (*jniEnv)->FindClass(jniEnv,
                                      "com/nic/nativeaes/utility/Utility");
    if (cls != NULL) {
        jmethodID mid = (*jniEnv)->GetStaticMethodID(jniEnv, cls, "stringToByte",
                                                     "(Ljava/lang/String;)[B");
        if (mid == NULL) return NULL;
        return (jbyteArray) (*jniEnv)->CallStaticObjectMethod(jniEnv, cls, mid,
                                                              data);
    }
}

jstring byteToString(JNIEnv *jniEnv, jobject obz, jbyteArray data) {
    jclass cls = (*jniEnv)->FindClass(jniEnv,
                                      "com/nic/nativeaes/utility/Utility");
    if (cls != NULL) {
        jmethodID mid = (*jniEnv)->GetStaticMethodID(jniEnv, cls, "byteToString",
                                                     "([B)Ljava/lang/String;");
        if (mid == NULL) return NULL;
        return (jstring) (*jniEnv)->CallStaticObjectMethod(jniEnv, cls, mid,
                                                           data);
    }
}

jstring getValue(JNIEnv *jniEnv1, jobject obz, jobject jobject1, jstring key) {
    jclass cls = (*jniEnv1)->GetObjectClass(jniEnv1, jobject1);

    if (cls != NULL) {
        jstring jstr = (*jniEnv1)->NewStringUTF(jniEnv1, key);
        jobject obj = (*jniEnv1)->AllocObject(jniEnv1, cls);
        jmethodID mid = (*jniEnv1)->GetMethodID(jniEnv1, cls, "getValue",
                                                "(Ljava/lang/String;)Ljava/lang/String;");
        if (mid == NULL) return NULL;
        jobject result = (jobject) (*jniEnv1)->CallObjectMethod(jniEnv1, obj, mid, jstr);
        const char *str = (*jniEnv1)->GetStringUTFChars(jniEnv1, (jstring) result,
                                                        NULL); // should be released but what a heck, it's a tutorial :)
        //LOGD("getValue()=%s", str);

        return (*jniEnv1)->NewStringUTF(jniEnv1, str);
    }
}

jstring concat(JNIEnv *env, jobject obz, jstring str1, jstring str2) {
    jbyte *str1x = (*env)->GetStringUTFChars(env, str1, NULL);
    jbyte *str2x = (*env)->GetStringUTFChars(env, str2, NULL);

    char *result = malloc(strlen(str1x) + strlen(str2x) + 1);
    strcpy(result, str1x);
    strcat(result, str2x);

    jstring retval = (*env)->NewStringUTF(env, result);
    (*env)->ReleaseStringUTFChars(env, str1, str1x);
    (*env)->ReleaseStringUTFChars(env, str2, str2x);
    free(result);

    return retval;
}

jstring getPkg(JNIEnv *env, jobject activity) {
    jclass android_content_Context = (*env)->GetObjectClass(env, activity);
    jmethodID midGetPackageName = (*env)->GetMethodID(env, android_content_Context,
                                                      "getPackageName", "()Ljava/lang/String;");
    jstring packageName = (jstring) (*env)->CallObjectMethod(env, activity, midGetPackageName);
    return packageName;
}

jboolean equals(JNIEnv *env, jstring jstring1, jstring jstring2) {
    const char *nativeString1 = (*env)->GetStringUTFChars(env, jstring1, 0);
    const char *nativeString2 = (*env)->GetStringUTFChars(env, jstring2, 0);
    int res = strncmp(nativeString1, nativeString2, strlen(nativeString1));
    (*env)->ReleaseStringUTFChars(env, jstring1, nativeString1);
    (*env)->ReleaseStringUTFChars(env, jstring2, nativeString2);
    if (res == 0) {
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

jboolean isCertValid(JNIEnv *env, jobject obj, jobject apiHelper) {
    jstring package = getValue(env, obj, apiHelper, "PACKAGE");
    jstring appName = getValue(env, obj, apiHelper, "APP_NAME");
    jstring buildType = getValue(env, obj, apiHelper, "BUILD_TYPE");
    jstring MD5 = getValue(env, obj, apiHelper, "MD5");
    jstring SHA1 = getValue(env, obj, apiHelper, "SHA1");
    jstring SHA256 = getValue(env, obj, apiHelper, "SHA256");

    LOGD("SYSTEM APP PACKAGE= %s", (*env)->GetStringUTFChars(env, (jstring) package, NULL));
    LOGD("SYSTEM APP NAME= %s", (*env)->GetStringUTFChars(env, (jstring) appName, NULL));
    LOGD("SYSTEM BUILD TYPE= %s", (*env)->GetStringUTFChars(env, (jstring) buildType, NULL));
    LOGD("SYSTEM MD5= %s", (*env)->GetStringUTFChars(env, (jstring) MD5, NULL));
    LOGD("SYSTEM SHA1= %s", (*env)->GetStringUTFChars(env, (jstring) SHA1, NULL));
    LOGD("SYSTEM SHA256= %s", (*env)->GetStringUTFChars(env, (jstring) SHA256, NULL));

    jstring clientPackage;
    jstring clientAppName;
    jstring clientBuildType = getValue(env, obj, apiHelper, "SYSTEM_BUILD_TYPE");
    jstring clientMD5;
    jstring clientSHA1;
    jstring clientSHA256;

    //LOGD("CLIENT BUILD TYPE= %s", (*env)->GetStringUTFChars(env, (jstring) clientBuildType, NULL));


    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID methodID = (*env)->GetStaticMethodID(env, cls, "getClientContext",
                                                   "()Landroid/content/Context;");
    jobject obz = (jobject) (*env)->CallStaticObjectMethod(env, cls, methodID);
    clientPackage = getPkg(env, obz);
    const char *pkg = (*env)->GetStringUTFChars(env, (jstring) clientPackage, NULL);
    //LOGD("APP PACKAGE= %s", pkg);


    jclass clz = (*env)->FindClass(env, "com/nic/nativeaes/utility/Utility");
    //if (clz != NULL) {
    jmethodID mid = (*env)->GetStaticMethodID(env, clz, "appLabel",
                                              "(Landroid/content/Context;)Ljava/lang/String;");
    if (mid == NULL) return NULL;
    clientAppName = (jstring) (*env)->CallStaticObjectMethod(env, clz, mid, obz);
    //LOGD("APP NAME= %s", (*env)->GetStringUTFChars(env, (jstring) clientAppName, NULL));

    mid = (*env)->GetStaticMethodID(env, clz, "getSingInfo",
                                    "(Landroid/content/Context;)Ljava/lang/String;");
    if (mid == NULL) return NULL;
    clientMD5 = (jstring) (*env)->CallStaticObjectMethod(env, clz, mid, obz);
    //LOGD("MD5= %s", (*env)->GetStringUTFChars(env, (jstring) clientMD5, NULL));

    mid = (*env)->GetStaticMethodID(env, clz, "getCertificateSHA1Fingerprint",
                                    "(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;");
    if (mid == NULL) return NULL;
    clientSHA1 = (jstring) (*env)->CallStaticObjectMethod(env, clz, mid, obz,
                                                          (*env)->NewStringUTF(env, "SHA1"));
    //LOGD("SHA1= %s", (*env)->GetStringUTFChars(env, (jstring) clientSHA1, NULL));

    mid = (*env)->GetStaticMethodID(env, clz, "getCertificateSHA1Fingerprint",
                                    "(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;");
    if (mid == NULL) return NULL;
    clientSHA256 = (jstring) (*env)->CallStaticObjectMethod(env, clz, mid, obz,
                                                            (*env)->NewStringUTF(env,
                                                                                 "SHA256"));
    //LOGD("SHA256= %s", (*env)->GetStringUTFChars(env, (jstring) clientSHA256, NULL));
    // }

    if (equals(env, package, clientPackage)
        && equals(env, appName, clientAppName)
        && equals(env, buildType, clientBuildType)
        && equals(env, MD5, clientMD5)
        && equals(env, SHA1, clientSHA1)
        && equals(env, SHA256, clientSHA256)) {
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

jstring
getResponse(JNIEnv *jniEnv1, jobject obz, jobject apiController, jstring apiBaseURL, jstring path,
            jstring inputData,
            jstring type, jstring mode) {

    jclass cls = (*jniEnv1)->GetObjectClass(jniEnv1, apiController);

    if (cls != NULL) {

        jobject obj = (*jniEnv1)->AllocObject(jniEnv1, cls);
        //const char *temp1 = (*jniEnv1)->GetStringUTFChars(jniEnv1, (jstring) apiBaseURL, NULL);
        //const char *temp2 = (*jniEnv1)->GetStringUTFChars(jniEnv1, (jstring) path, NULL);
        const char *temp3 = (*jniEnv1)->GetStringUTFChars(jniEnv1, (jstring) inputData, NULL);
        const char *temp4 = (*jniEnv1)->GetStringUTFChars(jniEnv1, (jstring) type, NULL);
        const char *temp5 = (*jniEnv1)->GetStringUTFChars(jniEnv1, (jstring) mode, NULL);
        //jstring baseURL = (*jniEnv1)->NewStringUTF(jniEnv1, temp1);
        //jstring apiPath = (*jniEnv1)->NewStringUTF(jniEnv1, temp1);

        jstring url = concat(jniEnv1, obj, apiBaseURL, path);
        const char *myURL = (*jniEnv1)->GetStringUTFChars(jniEnv1, (jstring) url, NULL);
        //LOGD("URL= %s", myURL);

        jstring input = (*jniEnv1)->NewStringUTF(jniEnv1, temp3);
        jstring methodType = (*jniEnv1)->NewStringUTF(jniEnv1, temp4);
        jstring sslMode = (*jniEnv1)->NewStringUTF(jniEnv1, temp5);

        jmethodID mid = (*jniEnv1)->GetMethodID(jniEnv1, cls, "getResponse",
                                                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
        if (mid == NULL) return NULL;
        jobject result = (jobject) (*jniEnv1)->CallObjectMethod(jniEnv1, obj, mid, url, input,
                                                                methodType, sslMode);
        const char *response = (*jniEnv1)->GetStringUTFChars(jniEnv1, (jstring) result,
                                                             NULL);
        (*jniEnv1)->DeleteLocalRef(jniEnv1, cls);
        (*jniEnv1)->DeleteLocalRef(jniEnv1, obj);
        //LOGD("SERVER_RESPONSE= %s", response);
        return (*jniEnv1)->NewStringUTF(jniEnv1, response);
    }
}

jbyteArray encrypt(JNIEnv *jniEnv1, jclass cls, jbyteArray jarray, jlong jtimestamp, jint jmode,
                   jstring requestIV, jstring requestKey) {

    unsigned int len = (unsigned int) ((*jniEnv1)->GetArrayLength(jniEnv1, jarray));
    if (len <= 0 || len >= MAX_LEN) {
        return NULL;
    }
    unsigned char *data = (unsigned char *) (*jniEnv1)->GetByteArrayElements(jniEnv1, jarray, NULL);
    if (!data) {
        return NULL;
    }
    const char *AES_IV = (*jniEnv1)->GetStringUTFChars(jniEnv1, requestIV, 0);
    const char *AES_KEY = (*jniEnv1)->GetStringUTFChars(jniEnv1, requestKey, 0);

    //need to release this string when done with it in order to
    //avoid memory leak

    //LOGD("%s",str);

    //(*env)->ReleaseStringUTFChars(env, requestIV, str);
    // const char *mystring = (*env)->GetStringUTFChars(env, requestIV, 0);

    //Calculate the fill length, when it is encrypted and the length is not an integer multiple of 16, it is filled, similar to the 3DES fill (DESede / CBC / PKCS5Padding)
    unsigned int mode = (unsigned int) jmode;
    unsigned int rest_len = len % AES_BLOCK_SIZE;

    unsigned int padding_len = ((ENCRYPT == mode) ? (AES_BLOCK_SIZE - rest_len) : 0);
    unsigned int src_len = len + padding_len;

    //Set the input
    unsigned char *input = (unsigned char *) malloc(src_len);
    memset(input, 0, src_len);
    memcpy(input, data, len);
    if (padding_len > 0) {
        memset(input + len, (unsigned char) padding_len, padding_len);
    }

    //data is no longer used
    (*jniEnv1)->ReleaseByteArrayElements(jniEnv1, jarray, data, 0);

    //Set the output buffer
    unsigned char *buff = (unsigned char *) malloc(src_len);
    if (!buff) {
        free(input);
        return NULL;
    }
    memset(buff, 0, src_len);

    //set key & iv
    unsigned int key_schedule[AES_BLOCK_SIZE * 4] = {0}; //> = 53 (here take 64)
    aes_key_setup(AES_KEY, key_schedule, AES_KEY_SIZE);

    //Perform encryption and decryption (CBC mode)
    if (mode == ENCRYPT) {
        aes_encrypt_cbc(input, src_len, buff, key_schedule, AES_KEY_SIZE,
                        AES_IV);
    } else {
        aes_decrypt_cbc(input, src_len, buff, key_schedule, AES_KEY_SIZE,
                        AES_IV);
    }
    //Calculate the fill length when decrypting
    if (ENCRYPT != mode) {
        unsigned char *ptr = buff;
        ptr += (src_len - 1);
        padding_len = (unsigned int) *ptr;
        if (padding_len > 0 && padding_len <= AES_BLOCK_SIZE) {
            src_len -= padding_len;
        }
        ptr = NULL;
    }

    //Set the return variable
    jbyteArray bytes = (*jniEnv1)->NewByteArray(jniEnv1, src_len);
    (*jniEnv1)->SetByteArrayRegion(jniEnv1, bytes, 0, src_len, (jbyte *) buff);
    //Memory release
    free(input);
    free(buff);

    return bytes;
}

JNIEXPORT jbyteArray JNICALL
Java_com_nic_nativeaes_wrapper_SecurityManager_aesProcessing(JNIEnv *jniEnv, jobject obj,
                                                             jbyteArray jarray,
                                                             jlong jtimestamp, jint jmode) {
    jclass cls = (*jniEnv)->GetObjectClass(jniEnv, obj);

    jmethodID mid = (*jniEnv)->GetStaticMethodID(jniEnv, cls, "getClientHelper",
                                                 "()Ljava/lang/Object;");
    jobject apiHelper = (jobject) (*jniEnv)->CallStaticObjectMethod(jniEnv, cls, mid);

    /*if (!isCertValid(jniEnv, obj, apiHelper)) {
       return 0;
   }*/

    jstring baseURL = getValue(jniEnv, obj, apiHelper, "API_BASE_URL");
    //jstring secretKey = getValue(jniEnv, obj, apiHelper, "SECRET_KEY");
    jstring IV = getValue(jniEnv, obj, apiHelper, "IV");

    jstring temp1 = getValue(jniEnv, obj, apiHelper, "VAL_1");
    jstring temp2 = getValue(jniEnv, obj, apiHelper, "VAL_2");

    jstring secretKey = getVal(jniEnv, obj, temp1, temp2);

    jbyteArray data = encrypt(jniEnv, cls, jarray, jtimestamp, jmode, IV, secretKey);
    return data;
}

JNIEXPORT jstring JNICALL
Java_com_nic_nativeaes_wrapper_SecurityManager_processRequest(JNIEnv *jniEnv, jobject obj,
                                                              jbyteArray jarray,
                                                              jlong jtimestamp, jstring apiPath,
                                                              jstring methodType, jstring sslMode) {
    jint jmode = ENCRYPT;//Encrypt
    jclass cls = (*jniEnv)->GetObjectClass(jniEnv, obj);
    jmethodID mid = (*jniEnv)->GetStaticMethodID(jniEnv, cls, "getClientHelper",
                                                 "()Ljava/lang/Object;");
    jobject apiHelper = (jobject) (*jniEnv)->CallStaticObjectMethod(jniEnv, cls, mid);

    /*if (!isCertValid(jniEnv, obj, apiHelper)) {
        return NULL;
    }*/


    jstring baseURL = getValue(jniEnv, obj, apiHelper, "API_BASE_URL");
    const char *temp = (*jniEnv)->GetStringUTFChars(jniEnv, (jstring) apiPath,
                                                    NULL);
    jstring path = getValue(jniEnv, obj, apiHelper, temp);
    //jstring secretKey = getValue(jniEnv, obj, apiHelper, "SECRET_KEY");
    jstring temp1 = getValue(jniEnv, obj, apiHelper, "VAL_1");
    jstring temp2 = getValue(jniEnv, obj, apiHelper, "VAL_2");
    jstring IV = getValue(jniEnv, obj, apiHelper, "IV");

    jstring secretKey = getVal(jniEnv, obj, temp1, temp2);

    jbyteArray data1 = encrypt(jniEnv, cls, jarray, jtimestamp, jmode, IV, secretKey);

    data1 = encodeDecodeBase64(jniEnv, obj, data1, ENCODE);
    jstring inputData = byteToString(jniEnv, obj, data1);
    //jstring inputData = jbyteArrayTojstring(jniEnv, data1);

    jmethodID methodID = (*jniEnv)->GetStaticMethodID(jniEnv, cls, "getApiController",
                                                      "()Ljava/lang/Object;");
    jobject apiController = (jobject) (*jniEnv)->CallStaticObjectMethod(jniEnv, cls, methodID);

    jstring response = getResponse(jniEnv, obj, apiController, baseURL, path, inputData,
                                   methodType, sslMode);

    jbyteArray result = stringToByte(jniEnv, obj, response);
    //jbyteArray result = jstringTojbyteArray(jniEnv, response);
    result = encodeDecodeBase64(jniEnv, obj, result, DECODE);
    result = encrypt(jniEnv, cls, result, jtimestamp, DECRYPT, IV, secretKey);
    return byteToString(jniEnv, obj, result);
    //return jbyteArrayTojstring(jniEnv, result);
}

JNIEXPORT jbyteArray JNICALL android_native_read(JNIEnv *env, jclass clazz,
                                                 jstring jstr, jlong jtimestam) {
    char *path = (char *) (*env)->GetStringUTFChars(env, jstr, NULL);
    if (!path) {
        return NULL;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return NULL;
    }
    (*env)->ReleaseStringUTFChars(env, jstr, path);

    char pBuf[READ_LEN + 1] = {0};
    fread(pBuf, 1, READ_LEN, fp);
    pBuf[READ_LEN] = 0;
    fclose(fp);

    jbyteArray bytes = (*env)->NewByteArray(env, READ_LEN);
    (*env)->SetByteArrayRegion(env, bytes, 0, READ_LEN, (jbyte *) pBuf);

    return bytes;
}

JNIEXPORT jbyteArray JNICALL android_native_getRequest(JNIEnv *env, jclass clazz) {
}

JNIEXPORT jbyteArray JNICALL android_native_postRequest(JNIEnv *env, jclass clazz) {
}

