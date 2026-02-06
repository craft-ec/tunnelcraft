package com.tunnelcraft.module

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.facebook.react.bridge.*
import com.facebook.react.modules.core.DeviceEventManagerModule
import com.tunnelcraft.vpn.TunnelCraftVpnService

/**
 * React Native Native Module for TunnelCraft VPN
 */
class TunnelCraftVPNModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext), ActivityEventListener {

    companion object {
        private const val TAG = "TunnelCraftVPN"
        private const val VPN_REQUEST_CODE = 1001

        // Connection states
        private const val STATE_DISCONNECTED = "disconnected"
        private const val STATE_CONNECTING = "connecting"
        private const val STATE_CONNECTED = "connected"
        private const val STATE_DISCONNECTING = "disconnecting"
        private const val STATE_ERROR = "error"
    }

    private var currentState = STATE_DISCONNECTED
    private var pendingConnectPromise: Promise? = null
    private var connectConfig: ReadableMap? = null

    init {
        reactContext.addActivityEventListener(this)
    }

    override fun getName(): String = "TunnelCraftVPN"

    // MARK: - Exported Methods

    @ReactMethod
    fun connect(config: ReadableMap, promise: Promise) {
        val activity = currentActivity
        if (activity == null) {
            promise.reject("E_NO_ACTIVITY", "No activity available")
            return
        }

        // Check for VPN permission
        val intent = VpnService.prepare(activity)
        if (intent != null) {
            // Need to request VPN permission
            pendingConnectPromise = promise
            connectConfig = config
            activity.startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            // Already have permission, connect directly
            startVpnService(config, promise)
        }
    }

    @ReactMethod
    fun disconnect(promise: Promise) {
        try {
            updateState(STATE_DISCONNECTING)

            val intent = Intent(reactApplicationContext, TunnelCraftVpnService::class.java).apply {
                action = TunnelCraftVpnService.ACTION_DISCONNECT
            }
            reactApplicationContext.startService(intent)

            updateState(STATE_DISCONNECTED)
            promise.resolve(null)
        } catch (e: Exception) {
            promise.reject("E_DISCONNECT_FAILED", e.message, e)
        }
    }

    @ReactMethod
    fun getStatus(promise: Promise) {
        val status = Arguments.createMap().apply {
            putString("state", currentState)
            putString("peerId", "")
            putInt("connectedPeers", 0)
            putInt("credits", 0)
            putNull("exitNode")
            putNull("errorMessage")
        }
        promise.resolve(status)
    }

    @ReactMethod
    fun isConnected(promise: Promise) {
        promise.resolve(currentState == STATE_CONNECTED)
    }

    @ReactMethod
    fun setPrivacyLevel(level: String, promise: Promise) {
        // Store in SharedPreferences for the VPN service to read
        val prefs = reactApplicationContext.getSharedPreferences("tunnelcraft", Context.MODE_PRIVATE)
        prefs.edit().putString("privacy_level", level).apply()
        promise.resolve(null)
    }

    @ReactMethod
    fun setCredits(credits: Double, promise: Promise) {
        val prefs = reactApplicationContext.getSharedPreferences("tunnelcraft", Context.MODE_PRIVATE)
        prefs.edit().putLong("credits", credits.toLong()).apply()
        promise.resolve(null)
    }

    @ReactMethod
    fun setMode(mode: String, promise: Promise) {
        val prefs = reactApplicationContext.getSharedPreferences("tunnelcraft", Context.MODE_PRIVATE)
        prefs.edit().putString("node_mode", mode).apply()
        // In production, this would call through JNI to TunnelCraftUnifiedNode.set_mode()
        promise.resolve(null)
    }

    @ReactMethod
    fun purchaseCredits(amount: Double, promise: Promise) {
        try {
            val prefs = reactApplicationContext.getSharedPreferences("tunnelcraft", Context.MODE_PRIVATE)
            val currentCredits = prefs.getLong("credits", 0)
            val newBalance = currentCredits + amount.toLong()
            prefs.edit().putLong("credits", newBalance).apply()

            val result = Arguments.createMap().apply {
                putDouble("balance", newBalance.toDouble())
            }
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("E_PURCHASE_FAILED", e.message, e)
        }
    }

    @ReactMethod
    fun request(params: ReadableMap, promise: Promise) {
        val method = params.getString("method") ?: "GET"
        val url = params.getString("url") ?: ""
        val body = if (params.hasKey("body")) params.getString("body") else null

        // Mock response (JNI integration deferred)
        try {
            val result = Arguments.createMap().apply {
                putInt("status", 200)
                putString("body", "{\"mock\":true,\"method\":\"$method\",\"url\":\"$url\",\"message\":\"Mock response from TunnelCraft\"}")
            }
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("E_REQUEST_FAILED", e.message, e)
        }
    }

    // Required for RN event emitter
    @ReactMethod
    fun addListener(eventName: String) {
        // Keep: Required for RN built-in event emitter
    }

    @ReactMethod
    fun removeListeners(count: Int) {
        // Keep: Required for RN built-in event emitter
    }

    // MARK: - Activity Result

    override fun onActivityResult(
        activity: Activity?,
        requestCode: Int,
        resultCode: Int,
        data: Intent?
    ) {
        if (requestCode == VPN_REQUEST_CODE) {
            val promise = pendingConnectPromise
            val config = connectConfig

            pendingConnectPromise = null
            connectConfig = null

            if (resultCode == Activity.RESULT_OK && promise != null && config != null) {
                startVpnService(config, promise)
            } else {
                promise?.reject("E_VPN_PERMISSION_DENIED", "VPN permission denied")
            }
        }
    }

    override fun onNewIntent(intent: Intent?) {
        // Not used
    }

    // MARK: - Private Methods

    private fun startVpnService(config: ReadableMap, promise: Promise) {
        try {
            updateState(STATE_CONNECTING)

            val intent = Intent(reactApplicationContext, TunnelCraftVpnService::class.java).apply {
                action = TunnelCraftVpnService.ACTION_CONNECT

                if (config.hasKey("privacyLevel")) {
                    putExtra(TunnelCraftVpnService.EXTRA_PRIVACY_LEVEL, config.getString("privacyLevel"))
                }
                if (config.hasKey("bootstrapPeer")) {
                    putExtra(TunnelCraftVpnService.EXTRA_BOOTSTRAP_PEER, config.getString("bootstrapPeer"))
                }
            }

            reactApplicationContext.startService(intent)

            // Note: In production, we'd wait for confirmation from the service
            updateState(STATE_CONNECTED)
            promise.resolve(null)

        } catch (e: Exception) {
            updateState(STATE_ERROR)
            promise.reject("E_CONNECT_FAILED", e.message, e)
        }
    }

    private fun updateState(state: String) {
        currentState = state
        sendEvent("onStateChange", state)
    }

    private fun sendEvent(eventName: String, data: Any?) {
        reactApplicationContext
            .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
            .emit(eventName, data)
    }
}
