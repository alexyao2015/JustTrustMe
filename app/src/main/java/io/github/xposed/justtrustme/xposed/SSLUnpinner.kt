package io.github.xposed.justtrustme.xposed

import android.annotation.TargetApi
import android.content.Context
import android.net.http.SslError
import android.net.http.X509TrustManagerExtensions
import android.os.Build
import android.util.Log
import android.webkit.SslErrorHandler
import android.webkit.WebView
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.XposedHelpers.ClassNotFoundError
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import org.apache.http.conn.ClientConnectionManager
import org.apache.http.conn.scheme.HostNameResolver
import org.apache.http.conn.scheme.PlainSocketFactory
import org.apache.http.conn.scheme.Scheme
import org.apache.http.conn.scheme.SchemeRegistry
import org.apache.http.conn.ssl.SSLSocketFactory
import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.impl.conn.SingleClientConnManager
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager
import org.apache.http.params.HttpParams
import java.io.IOException
import java.net.Socket
import java.net.UnknownHostException
import java.security.KeyManagementException
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManager
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager

class SSLUnpinner : IXposedHookLoadPackage {
    val tag = "SSLUnpinner"
    fun log(message: String) {
        XposedBridge.log("${tag}: $message")
        Log.d(tag, message)
    }
    
    var currentPackageName: String = ""

    @Throws(Throwable::class)
    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        currentPackageName = lpparam.packageName


        /* Apache Hooks */
        /* external/apache-http/src/org/apache/http/impl/client/DefaultHttpClient.java */
        /* public DefaultHttpClient() */
        if (hasDefaultHTTPClient()) {
            log(
                "Hooking DefaultHTTPClient for: $currentPackageName"
            )
            XposedHelpers.findAndHookConstructor(
                DefaultHttpClient::class.java,
                object : XC_MethodHook() {
                    @Throws(Throwable::class)
                    override fun afterHookedMethod(param: MethodHookParam) {
                        XposedHelpers.setObjectField(param.thisObject, "defaultParams", null)
                        XposedHelpers.setObjectField(param.thisObject, "connManager", sCCM)
                    }
                })

            /* external/apache-http/src/org/apache/http/impl/client/DefaultHttpClient.java */
            /* public DefaultHttpClient(HttpParams params) */
            log(
                "Hooking DefaultHTTPClient(HttpParams) for: $currentPackageName"
            )
            XposedHelpers.findAndHookConstructor(
                DefaultHttpClient::class.java,
                HttpParams::class.java, object : XC_MethodHook() {
                    @Throws(Throwable::class)
                    override fun afterHookedMethod(param: MethodHookParam) {
                        XposedHelpers.setObjectField(
                            param.thisObject,
                            "defaultParams",
                            param.args[0] as HttpParams
                        )
                        XposedHelpers.setObjectField(param.thisObject, "connManager", sCCM)
                    }
                })

            /* external/apache-http/src/org/apache/http/impl/client/DefaultHttpClient.java */
            /* public DefaultHttpClient(ClientConnectionManager conman, HttpParams params) */
            log(
                "Hooking DefaultHTTPClient(ClientConnectionManager, HttpParams) for: $currentPackageName"
            )
            XposedHelpers.findAndHookConstructor(
                DefaultHttpClient::class.java,
                ClientConnectionManager::class.java,
                HttpParams::class.java, object : XC_MethodHook() {
                    @Throws(Throwable::class)
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val params = param.args[1] as HttpParams

                        XposedHelpers.setObjectField(param.thisObject, "defaultParams", params)
                        XposedHelpers.setObjectField(
                            param.thisObject,
                            "connManager",
                            getCCM(param.args[0], params)
                        )
                    }
                })
        }

        XposedHelpers.findAndHookMethod(
            X509TrustManagerExtensions::class.java, "checkServerTrusted",
            Array<X509Certificate>::class.java,
            String::class.java,
            String::class.java, object : XC_MethodReplacement() {
                @Throws(Throwable::class)
                override fun replaceHookedMethod(param: MethodHookParam): Any {
                    return param.args[0]
                }
            })

        XposedHelpers.findAndHookMethod(
            "android.security.net.config.NetworkSecurityTrustManager",
            lpparam.classLoader,
            "checkPins",
            MutableList::class.java,
            XC_MethodReplacement.DO_NOTHING
        )

        /* external/apache-http/src/org/apache/http/conn/ssl/SSLSocketFactory.java */
        /* public SSLSocketFactory( ... ) */
        try {
            log(
                "Hooking SSLSocketFactory(String, KeyStore, String, KeyStore) for: $currentPackageName"
            )
            XposedHelpers.findAndHookConstructor(
                SSLSocketFactory::class.java,
                String::class.java,
                KeyStore::class.java,
                String::class.java,
                KeyStore::class.java,
                SecureRandom::class.java,
                HostNameResolver::class.java, object : XC_MethodHook() {
                    @Throws(Throwable::class)
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val algorithm = param.args[0] as String
                        val keystore = param.args[1] as KeyStore
                        val keystorePassword = param.args[2] as String
                        val random = param.args[4] as SecureRandom

                        var keymanagers: Array<KeyManager?>? = null
                        var trustmanagers: Array<TrustManager>? = null

                        if (keystore != null) {
                            keymanagers = XposedHelpers.callStaticMethod(
                                SSLSocketFactory::class.java,
                                "createKeyManagers",
                                keystore,
                                keystorePassword
                            ) as Array<KeyManager?>
                        }

                        trustmanagers = arrayOf<TrustManager>(trustManager)

                        XposedHelpers.setObjectField(
                            param.thisObject,
                            "sslcontext",
                            SSLContext.getInstance(algorithm)
                        )
                        XposedHelpers.callMethod(
                            XposedHelpers.getObjectField(
                                param.thisObject,
                                "sslcontext"
                            ), "init", keymanagers, trustmanagers, random
                        )
                        XposedHelpers.setObjectField(
                            param.thisObject, "socketfactory",
                            XposedHelpers.callMethod(
                                XposedHelpers.getObjectField(
                                    param.thisObject,
                                    "sslcontext"
                                ), "getSocketFactory"
                            )
                        )
                    }
                })


            /* external/apache-http/src/org/apache/http/conn/ssl/SSLSocketFactory.java */
            /* public static SSLSocketFactory getSocketFactory() */
            log(
                "Hooking static SSLSocketFactory(String, KeyStore, String, KeyStore) for: $currentPackageName"
            )
            XposedHelpers.findAndHookMethod(
                "org.apache.http.conn.ssl.SSLSocketFactory",
                lpparam.classLoader,
                "getSocketFactory",
                object : XC_MethodReplacement() {
                    @Throws(Throwable::class)
                    override fun replaceHookedMethod(param: MethodHookParam): Any {
                        return XposedHelpers.newInstance(SSLSocketFactory::class.java) as SSLSocketFactory
                    }
                })
        } catch (e: NoClassDefFoundError) {
            log(
                "NoClassDefFoundError SSLSocketFactory HostNameResolver for: $currentPackageName"
            )
        }

        /* external/apache-http/src/org/apache/http/conn/ssl/SSLSocketFactory.java */
        /* public boolean isSecure(Socket) */
        log(
            "Hooking SSLSocketFactory(Socket) for: $currentPackageName"
        )
        XposedHelpers.findAndHookMethod(
            "org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader, "isSecure",
            Socket::class.java, XC_MethodReplacement.DO_NOTHING
        )

        /* JSSE Hooks */
        /* libcore/luni/src/main/java/javax/net/ssl/TrustManagerFactory.java */
        /* public final TrustManager[] getTrustManager() */
        log(
            "Hooking TrustManagerFactory.getTrustManagers() for: $currentPackageName"
        )
        XposedHelpers.findAndHookMethod(
            "javax.net.ssl.TrustManagerFactory",
            lpparam.classLoader,
            "getTrustManagers",
            object : XC_MethodHook() {
                @Throws(Throwable::class)
                override fun afterHookedMethod(param: MethodHookParam) {
                    if (hasTrustManagerImpl()) {
                        val cls = XposedHelpers.findClass(
                            "com.android.org.conscrypt.TrustManagerImpl",
                            lpparam.classLoader
                        )

                        val managers = param.result as Array<TrustManager>
                        if (managers.size > 0 && cls.isInstance(managers[0])) return
                    }

                    param.result = arrayOf<TrustManager>(trustManager)
                }
            })

        /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
        /* public void setDefaultHostnameVerifier(HostnameVerifier) */
        log(
            "Hooking HttpsURLConnection.setDefaultHostnameVerifier for: $currentPackageName"
        )
        XposedHelpers.findAndHookMethod(
            "javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setDefaultHostnameVerifier",
            HostnameVerifier::class.java, XC_MethodReplacement.DO_NOTHING
        )

        /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
        /* public void setSSLSocketFactory(SSLSocketFactory) */
        log(
            "Hooking HttpsURLConnection.setSSLSocketFactory for: $currentPackageName"
        )
        XposedHelpers.findAndHookMethod(
            "javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setSSLSocketFactory",
            javax.net.ssl.SSLSocketFactory::class.java, XC_MethodReplacement.DO_NOTHING
        )

        /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
        /* public void setHostnameVerifier(HostNameVerifier) */
        log(
            "Hooking HttpsURLConnection.setHostnameVerifier for: $currentPackageName"
        )
        XposedHelpers.findAndHookMethod(
            "javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setHostnameVerifier",
            HostnameVerifier::class.java, XC_MethodReplacement.DO_NOTHING
        )


        /* WebView Hooks */
        /* frameworks/base/core/java/android/webkit/WebViewClient.java */
        /* public void onReceivedSslError(Webview, SslErrorHandler, SslError) */
        log(
            "Hooking WebViewClient.onReceivedSslError(WebView, SslErrorHandler, SslError) for: $currentPackageName"
        )

        XposedHelpers.findAndHookMethod("android.webkit.WebViewClient",
            lpparam.classLoader,
            "onReceivedSslError",
            WebView::class.java,
            SslErrorHandler::class.java,
            SslError::class.java,
            object : XC_MethodReplacement() {
                @Throws(Throwable::class)
                override fun replaceHookedMethod(param: MethodHookParam): Any? {
                    (param.args[1] as SslErrorHandler).proceed()
                    return null
                }
            })

        /* frameworks/base/core/java/android/webkit/WebViewClient.java */
        /* public void onReceivedError(WebView, int, String, String) */
        log(
            "Hooking WebViewClient.onReceivedSslError(WebView, int, string, string) for: $currentPackageName"
        )

        XposedHelpers.findAndHookMethod(
            "android.webkit.WebViewClient", lpparam.classLoader, "onReceivedError",
            WebView::class.java,
            Int::class.javaPrimitiveType,
            String::class.java,
            String::class.java, XC_MethodReplacement.DO_NOTHING
        )

        //SSLContext.init >> (null,ImSureItsLegitTrustManager,null)
        XposedHelpers.findAndHookMethod("javax.net.ssl.SSLContext", lpparam.classLoader, "init",
            Array<KeyManager>::class.java,
            Array<TrustManager>::class.java,
            SecureRandom::class.java, object : XC_MethodHook() {
                @Throws(Throwable::class)
                override fun beforeHookedMethod(param: MethodHookParam) {
                    param.args[0] = null
                    param.args[1] = arrayOf<TrustManager>(trustManager)
                    param.args[2] = null
                }
            })

        // Multi-dex support: https://github.com/rovo89/XposedBridge/issues/30#issuecomment-68486449
        XposedHelpers.findAndHookMethod("android.app.Application",
            lpparam.classLoader,
            "attach",
            Context::class.java,
            object : XC_MethodHook() {
                @Throws(Throwable::class)
                override fun afterHookedMethod(param: MethodHookParam) {
                    // Hook OkHttp or third party libraries.
                    val context = param.args[0] as Context
                    processOkHttp(context.classLoader)
                    processHttpClientAndroidLib(context.classLoader)
                    processXutils(context.classLoader)
                }
            }
        )

        /* Only for newer devices should we try to hook TrustManagerImpl */
        if (hasTrustManagerImpl()) {
            /* TrustManagerImpl Hooks */
            /* external/conscrypt/src/platform/java/org/conscrypt/TrustManagerImpl.java */
            log(
                "Hooking com.android.org.conscrypt.TrustManagerImpl for: $currentPackageName"
            )

            /* public void checkServerTrusted(X509Certificate[] chain, String authType) */
            XposedHelpers.findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl",
                lpparam.classLoader,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                object : XC_MethodReplacement() {
                    @Throws(Throwable::class)
                    override fun replaceHookedMethod(param: MethodHookParam): Any {
                        return 0
                    }
                })

            /* public List<X509Certificate> checkServerTrusted(X509Certificate[] chain,
                                    String authType, String host) throws CertificateException */
            XposedHelpers.findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl",
                lpparam.classLoader,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                String::class.java,
                object : XC_MethodReplacement() {
                    @Throws(Throwable::class)
                    override fun replaceHookedMethod(param: MethodHookParam): Any {
                        val list = ArrayList<X509Certificate>()
                        return list
                    }
                })


            /* public List<X509Certificate> checkServerTrusted(X509Certificate[] chain,
                                    String authType, SSLSession session) throws CertificateException */
            XposedHelpers.findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl",
                lpparam.classLoader,
                "checkServerTrusted",
                Array<X509Certificate>::class.java,
                String::class.java,
                SSLSession::class.java,
                object : XC_MethodReplacement() {
                    @Throws(Throwable::class)
                    override fun replaceHookedMethod(param: MethodHookParam): Any {
                        val list = ArrayList<X509Certificate>()
                        return list
                    }
                })

            try {
                XposedHelpers.findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl",
                    lpparam.classLoader,
                    "checkTrusted",
                    Array<X509Certificate>::class.java,
                    String::class.java,
                    SSLSession::class.java,
                    SSLParameters::class.java,
                    Boolean::class.javaPrimitiveType,
                    object : XC_MethodReplacement() {
                        @Throws(Throwable::class)
                        override fun replaceHookedMethod(param: MethodHookParam): Any {
                            val list = ArrayList<X509Certificate>()
                            return list
                        }
                    })


                XposedHelpers.findAndHookMethod("com.android.org.conscrypt.TrustManagerImpl",
                    lpparam.classLoader,
                    "checkTrusted",
                    Array<X509Certificate>::class.java,
                    ByteArray::class.java,
                    ByteArray::class.java,
                    String::class.java,
                    String::class.java,
                    Boolean::class.javaPrimitiveType,
                    object : XC_MethodReplacement() {
                        @Throws(Throwable::class)
                        override fun replaceHookedMethod(param: MethodHookParam): Any {
                            val list = ArrayList<X509Certificate>()
                            return list
                        }
                    })
            } catch (e: NoSuchMethodError) {
            }
        }
    } // End Hooks

    /* Helpers */ // Check for TrustManagerImpl class
    fun hasTrustManagerImpl(): Boolean {
        try {
            Class.forName("com.android.org.conscrypt.TrustManagerImpl")
        } catch (e: ClassNotFoundException) {
            return false
        }
        return true
    }

    fun hasDefaultHTTPClient(): Boolean {
        try {
            Class.forName("org.apache.http.impl.client.DefaultHttpClient")
        } catch (e: ClassNotFoundException) {
            return false
        }
        return true
    }

    private val emptySSLFactory: javax.net.ssl.SSLSocketFactory?
        get() {
            try {
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, arrayOf<TrustManager>(trustManager), null)
                return sslContext.socketFactory
            } catch (e: NoSuchAlgorithmException) {
                return null
            } catch (e: KeyManagementException) {
                return null
            }
        }

    val sCCM: ClientConnectionManager?
        //Create a SingleClientConnManager that trusts everyone!
        get() {
            val trustStore: KeyStore
            try {
                trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
                trustStore.load(null, null)

                val sf: SSLSocketFactory = TrustAllSSLSocketFactory(trustStore)
                sf.hostnameVerifier = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER

                val registry = SchemeRegistry()
                registry.register(Scheme("http", PlainSocketFactory.getSocketFactory(), 80))
                registry.register(Scheme("https", sf, 443))

                val ccm: ClientConnectionManager = SingleClientConnManager(null, registry)

                return ccm
            } catch (e: Exception) {
                return null
            }
        }

    //This function creates a ThreadSafeClientConnManager that trusts everyone!
    fun getTSCCM(params: HttpParams?): ClientConnectionManager? {
        val trustStore: KeyStore
        try {
            trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
            trustStore.load(null, null)

            val sf: SSLSocketFactory = TrustAllSSLSocketFactory(trustStore)
            sf.hostnameVerifier = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER

            val registry = SchemeRegistry()
            registry.register(Scheme("http", PlainSocketFactory.getSocketFactory(), 80))
            registry.register(Scheme("https", sf, 443))

            val ccm: ClientConnectionManager = ThreadSafeClientConnManager(params, registry)

            return ccm
        } catch (e: Exception) {
            return null
        }
    }

    //This function determines what object we are dealing with.
    fun getCCM(o: Any, params: HttpParams?): ClientConnectionManager? {
        val className = o.javaClass.simpleName

        if (className == "SingleClientConnManager") {
            return sCCM
        } else if (className == "ThreadSafeClientConnManager") {
            return getTSCCM(params)
        }

        return null
    }

    private fun processXutils(classLoader: ClassLoader) {
        log(
            "Hooking org.xutils.http.RequestParams.setSslSocketFactory(SSLSocketFactory) (3) for: $currentPackageName"
        )
        try {
            classLoader.loadClass("org.xutils.http.RequestParams")
            XposedHelpers.findAndHookMethod("org.xutils.http.RequestParams",
                classLoader,
                "setSslSocketFactory",
                javax.net.ssl.SSLSocketFactory::class.java,
                object : XC_MethodHook() {
                    @Throws(Throwable::class)
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        super.beforeHookedMethod(param)
                        param.args[0] = emptySSLFactory
                    }
                })
            XposedHelpers.findAndHookMethod("org.xutils.http.RequestParams",
                classLoader,
                "setHostnameVerifier",
                HostnameVerifier::class.java,
                object : XC_MethodHook() {
                    @Throws(Throwable::class)
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        super.beforeHookedMethod(param)
                        param.args[0] = ImSureItsLegitHostnameVerifier()
                    }
                })
        } catch (e: Exception) {
            log(
                "org.xutils.http.RequestParams not found in $currentPackageName-- not hooking"
            )
        }
    }

    fun processOkHttp(classLoader: ClassLoader) {
        /* hooking OKHTTP by SQUAREUP */
        /* com/squareup/okhttp/CertificatePinner.java available online @ https://github.com/square/okhttp/blob/master/okhttp/src/main/java/com/squareup/okhttp/CertificatePinner.java */
        /* public void check(String hostname, List<Certificate> peerCertificates) throws SSLPeerUnverifiedException{}*/
        /* Either returns true or a exception so blanket return true */
        /* Tested against version 2.5 */
        log(
            "Hooking com.squareup.okhttp.CertificatePinner.check(String,List) (2.5) for: $currentPackageName"
        )

        try {
            classLoader.loadClass("com.squareup.okhttp.CertificatePinner")
            XposedHelpers.findAndHookMethod("com.squareup.okhttp.CertificatePinner",
                classLoader,
                "check",
                String::class.java,
                MutableList::class.java,
                object : XC_MethodReplacement() {
                    @Throws(Throwable::class)
                    override fun replaceHookedMethod(methodHookParam: MethodHookParam): Any {
                        return true
                    }
                })
        } catch (e: ClassNotFoundException) {
            // pass
            log(
                "OKHTTP 2.5 not found in $currentPackageName-- not hooking"
            )
        }

        //https://github.com/square/okhttp/blob/parent-3.0.1/okhttp/src/main/java/okhttp3/CertificatePinner.java#L144
        log(
            "Hooking okhttp3.CertificatePinner.check(String,List) (3.x) for: $currentPackageName"
        )

        try {
            classLoader.loadClass("okhttp3.CertificatePinner")
            XposedHelpers.findAndHookMethod(
                "okhttp3.CertificatePinner",
                classLoader,
                "check",
                String::class.java,
                MutableList::class.java,
                XC_MethodReplacement.DO_NOTHING
            )
        } catch (e: ClassNotFoundException) {
            log(
                "OKHTTP 3.x not found in $currentPackageName -- not hooking"
            )
            // pass
        }

        //https://github.com/square/okhttp/blob/parent-3.0.1/okhttp/src/main/java/okhttp3/internal/tls/OkHostnameVerifier.java
        try {
            classLoader.loadClass("okhttp3.internal.tls.OkHostnameVerifier")
            XposedHelpers.findAndHookMethod("okhttp3.internal.tls.OkHostnameVerifier",
                classLoader,
                "verify",
                String::class.java,
                SSLSession::class.java,
                object : XC_MethodReplacement() {
                    @Throws(Throwable::class)
                    override fun replaceHookedMethod(methodHookParam: MethodHookParam): Any {
                        return true
                    }
                })
        } catch (e: ClassNotFoundException) {
            log(
                "OKHTTP 3.x not found in $currentPackageName -- not hooking OkHostnameVerifier.verify(String, SSLSession)"
            )
            // pass
        }

        //https://github.com/square/okhttp/blob/parent-3.0.1/okhttp/src/main/java/okhttp3/internal/tls/OkHostnameVerifier.java
        try {
            classLoader.loadClass("okhttp3.internal.tls.OkHostnameVerifier")
            XposedHelpers.findAndHookMethod("okhttp3.internal.tls.OkHostnameVerifier",
                classLoader,
                "verify",
                String::class.java,
                X509Certificate::class.java,
                object : XC_MethodReplacement() {
                    @Throws(Throwable::class)
                    override fun replaceHookedMethod(methodHookParam: MethodHookParam): Any {
                        return true
                    }
                })
        } catch (e: ClassNotFoundException) {
            log(
                "OKHTTP 3.x not found in $currentPackageName -- not hooking OkHostnameVerifier.verify(String, X509)("
            )
            // pass
        }

        //https://github.com/square/okhttp/blob/okhttp_4.2.x/okhttp/src/main/java/okhttp3/CertificatePinner.kt
        log(
            "Hooking okhttp3.CertificatePinner.check(String,List) (4.2.0+) for: $currentPackageName"
        )

        try {
            classLoader.loadClass("okhttp3.CertificatePinner")
            XposedHelpers.findAndHookMethod(
                "okhttp3.CertificatePinner",
                classLoader,
                "check\$okhttp",
                String::class.java,
                "kotlin.jvm.functions.Function0",
                XC_MethodReplacement.DO_NOTHING
            )
        } catch (e: ClassNotFoundError) {
            log(
                "OKHTTP 4.2.0+ (check\$okhttp) not found in $currentPackageName -- not hooking"
            )
            // pass
        } catch (e: ClassNotFoundException) {
            log(
                "OKHTTP 4.2.0+ (check\$okhttp) not found in $currentPackageName -- not hooking"
            )
        } catch (e: NoSuchMethodError) {
            log(
                "OKHTTP 4.2.0+ (check\$okhttp) not found in $currentPackageName -- not hooking"
            )
        }

        try {
            classLoader.loadClass("okhttp3.CertificatePinner")
            XposedHelpers.findAndHookMethod(
                "okhttp3.CertificatePinner",
                classLoader,
                "check",
                String::class.java,
                MutableList::class.java,
                XC_MethodReplacement.DO_NOTHING
            )
        } catch (e: ClassNotFoundError) {
            log(
                "OKHTTP 4.2.0+ (check) not found in $currentPackageName -- not hooking"
            )
            // pass
        } catch (e: ClassNotFoundException) {
            log(
                "OKHTTP 4.2.0+ (check) not found in $currentPackageName -- not hooking"
            )
        } catch (e: NoSuchMethodError) {
            log(
                "OKHTTP 4.2.0+ (check) not found in $currentPackageName -- not hooking"
            )
        }
    }

    fun processHttpClientAndroidLib(classLoader: ClassLoader) {
        /* httpclientandroidlib Hooks */
        /* public final void verify(String host, String[] cns, String[] subjectAlts, boolean strictWithSubDomains) throws SSLException */
        log(
            "Hooking AbstractVerifier.verify(String, String[], String[], boolean) for: $currentPackageName"
        )

        try {
            classLoader.loadClass("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier")
            XposedHelpers.findAndHookMethod(
                "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier", classLoader, "verify",
                String::class.java,
                Array<String>::class.java,
                Array<String>::class.java,
                Boolean::class.javaPrimitiveType,
                XC_MethodReplacement.DO_NOTHING
            )
        } catch (e: ClassNotFoundException) {
            // pass
            log(
                "httpclientandroidlib not found in $currentPackageName-- not hooking"
            )
        }
    }

    @TargetApi(Build.VERSION_CODES.N)
    private inner class ImSureItsLegitExtendedTrustManager : X509ExtendedTrustManager() {
        @Throws(CertificateException::class)
        override fun checkClientTrusted(
            chain: Array<X509Certificate>,
            authType: String,
            socket: Socket
        ) {
        }

        @Throws(CertificateException::class)
        override fun checkServerTrusted(
            chain: Array<X509Certificate>,
            authType: String,
            socket: Socket
        ) {
        }

        @Throws(CertificateException::class)
        override fun checkClientTrusted(
            chain: Array<X509Certificate>,
            authType: String,
            engine: SSLEngine
        ) {
        }

        @Throws(CertificateException::class)
        override fun checkServerTrusted(
            chain: Array<X509Certificate>,
            authType: String,
            engine: SSLEngine
        ) {
        }

        @Throws(CertificateException::class)
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
        }

        @Throws(CertificateException::class)
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        }

        override fun getAcceptedIssuers(): Array<X509Certificate?> {
            return arrayOfNulls(0)
        }
    }

    private inner class ImSureItsLegitTrustManager : X509TrustManager {
        @Throws(CertificateException::class)
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
        }

        @Throws(CertificateException::class)
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        }

        @Throws(CertificateException::class)
        fun checkServerTrusted(
            chain: Array<X509Certificate?>?,
            authType: String?,
            host: String?
        ): List<X509Certificate> {
            val list = ArrayList<X509Certificate>()
            return list
        }

        override fun getAcceptedIssuers(): Array<X509Certificate?> {
            return arrayOfNulls(0)
        }
    }

    private val trustManager: X509TrustManager
        get() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            ImSureItsLegitExtendedTrustManager()
        } else {
            ImSureItsLegitTrustManager()
        }

    private inner class ImSureItsLegitHostnameVerifier : HostnameVerifier {
        override fun verify(hostname: String, session: SSLSession): Boolean {
            return true
        }
    }

    /* This class creates a SSLSocket that trusts everyone. */
    inner class TrustAllSSLSocketFactory(truststore: KeyStore?) : SSLSocketFactory(truststore) {
        var sslContext: SSLContext = SSLContext.getInstance("TLS")

        init {
            val tm: TrustManager = object : X509TrustManager {
                @Throws(CertificateException::class)
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                }

                @Throws(CertificateException::class)
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                }

                override fun getAcceptedIssuers(): Array<X509Certificate>? {
                    return null
                }
            }

            sslContext.init(null, arrayOf(tm), null)
        }

        @Throws(IOException::class, UnknownHostException::class)
        override fun createSocket(
            socket: Socket,
            host: String,
            port: Int,
            autoClose: Boolean
        ): Socket {
            return sslContext.socketFactory.createSocket(socket, host, port, autoClose)
        }

        @Throws(IOException::class)
        override fun createSocket(): Socket {
            return sslContext.socketFactory.createSocket()
        }
    }
}