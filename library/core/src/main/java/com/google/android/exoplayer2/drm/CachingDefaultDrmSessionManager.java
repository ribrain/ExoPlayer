package com.google.android.exoplayer2.drm;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
import android.util.Log;
import android.util.Pair;



import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.extractor.mp4.PsshAtomUtil;
import com.google.android.exoplayer2.upstream.DefaultHttpDataSourceFactory;
import com.google.android.exoplayer2.util.Util;


import java.util.Arrays;
import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;


import static com.google.android.exoplayer2.drm.DefaultDrmSessionManager.MODE_DOWNLOAD;
import static com.google.android.exoplayer2.drm.DefaultDrmSessionManager.MODE_QUERY;

public class CachingDefaultDrmSessionManager<T extends ExoMediaCrypto> implements DrmSessionManager<T> {

    private final SharedPreferences drmkeys;
    public static final String TAG="CachingDRM";
    private final DefaultDrmSessionManager<T> delegateDefaultDrmSessionManager;
    private OfflineLicenseHelper<FrameworkMediaCrypto> offlineLicenseHelper;
    private final UUID uuid;
    private final AtomicBoolean pending = new AtomicBoolean(false);
    private byte[] schemeInitD;

    public interface EventListener {

        /**
         * Called each time keys are loaded.
         */
        void onDrmKeysLoaded();

        /**
         * Called when a drm error occurs.
         *
         * @param e The corresponding exception.
         */
        void onDrmSessionManagerError(Exception e);

        /**
         * Called each time offline keys are restored.
         */
        void onDrmKeysRestored();

        /**
         * Called each time offline keys are removed.
         */
        void onDrmKeysRemoved();

    }

    public CachingDefaultDrmSessionManager(Context context, UUID uuid, ExoMediaDrm<T> mediaDrm, MediaDrmCallback callback, HashMap<String, String> optionalKeyRequestParameters, final Handler eventHandler, final EventListener eventListener) {
        //super(uuid, mediaDrm, callback, optionalKeyRequestParameters, eventHandler, eventListener);
        this.uuid = uuid;
        DefaultDrmSessionManager.EventListener eventListenerInternal = new DefaultDrmSessionManager.EventListener() {

            @Override
            public void onDrmKeysLoaded() {
                saveDrmKeys();
                pending.set(false);
                if (eventListener!=null) eventListener.onDrmKeysLoaded();
            }

            @Override
            public void onDrmSessionManagerError(Exception e) {
                pending.set(false);
                if (eventListener!=null) eventListener.onDrmSessionManagerError(e);
            }

            @Override
            public void onDrmKeysRestored() {
                saveDrmKeys();
                pending.set(false);
                if (eventListener!=null) eventListener.onDrmKeysRestored();
            }

            @Override
            public void onDrmKeysRemoved() {
                if (eventListener!=null) eventListener.onDrmKeysRemoved();
            }
        };
        delegateDefaultDrmSessionManager = new DefaultDrmSessionManager<T>(uuid, mediaDrm, callback, optionalKeyRequestParameters, eventHandler, eventListenerInternal);
        drmkeys = context.getSharedPreferences("drmkeys", Context.MODE_PRIVATE);
            DefaultHttpDataSourceFactory factory = new DefaultHttpDataSourceFactory("TEST");
            offlineLicenseHelper = new OfflineLicenseHelper(mediaDrm, callback, optionalKeyRequestParameters );
    }

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public void saveDrmKeys() {
        byte[] offlineLicenseKeySetId = delegateDefaultDrmSessionManager.getOfflineLicenseKeySetId();
        if (offlineLicenseKeySetId==null) {
            Log.i(TAG,"Failed to download offline license key");
        } else {
            Log.i(TAG,"Storing downloaded offline license key for "+bytesToHex(schemeInitD)+": "+bytesToHex(offlineLicenseKeySetId));
            storeKeySetId(schemeInitD, offlineLicenseKeySetId);
        }
    }

    @Override
    public boolean canAcquireSession(DrmInitData drmInitData) {
        DrmInitData.SchemeData schemeData = drmInitData.get(uuid);
        if (schemeData == null) {
              // No data for this manager's scheme.
              return false;
        }

        String schemeType = schemeData.type;
        if (schemeType == null || C.CENC_TYPE_cenc.equals(schemeType)) {
            // If there is no scheme information, assume patternless AES-CTR.
            return true;
        } else if (C.CENC_TYPE_cbc1.equals(schemeType) || C.CENC_TYPE_cbcs.equals(schemeType)
               || C.CENC_TYPE_cens.equals(schemeType)) {
             // AES-CBC and pattern encryption are supported on API 24 onwards.
             return Util.SDK_INT >= 24;
        }
        // Unknown schemes, assume one of them is supported.
        return true;

    }

    @Override
    public DrmSession<T> acquireSession(Looper playbackLooper, DrmInitData drmInitData) {

        if (pending.getAndSet(true)) {
            Log.i(TAG,"Already pending request");
            return delegateDefaultDrmSessionManager.acquireSession(playbackLooper, drmInitData);
        }
        Log.i(TAG,"Request, was not yet pending");


        // First check if we already have this license in local storage and if it's still valid.
        DrmInitData.SchemeData schemeData = drmInitData.get(uuid);
        schemeInitD = schemeData.data;
        Log.i(TAG,"Request for key for init data "+bytesToHex(schemeInitD));
        if (Util.SDK_INT < 21) {
            // Prior to L the Widevine CDM required data to be extracted from the PSSH atom.
            byte[] psshData = PsshAtomUtil.parseSchemeSpecificData(schemeInitD, C.WIDEVINE_UUID);
            if (psshData == null) {
                // Extraction failed. schemeData isn't a Widevine PSSH atom, so leave it unchanged.
            } else {
                schemeInitD = psshData;
            }
        }
        byte[] cachedKeySetId=loadKeySetId(schemeInitD);
        if (cachedKeySetId!=null) {
            //Load successful.
            Log.i(TAG,"Cached key set found "+bytesToHex(cachedKeySetId));

            Pair<Long, Long> remainingSec = null;
            try {
                remainingSec = offlineLicenseHelper.getLicenseDurationRemainingSec(cachedKeySetId);
                Log.i(TAG,"Validity: "+remainingSec.first+" sec / "+remainingSec.second+" sec");

                if ((remainingSec.first < 4*60*60 ) || (remainingSec.second<4*60*60)) {
                    Log.i(TAG,"License should be renewed.");
                    removeKeySetId(cachedKeySetId);
                    try {
                        offlineLicenseHelper.release();
                    }catch (Exception ignore) {
                        Log.i(TAG,"Error in releasing expired license. Ignore.");
                    }
                    cachedKeySetId=null;

                }
                else {
                    if (!Arrays.equals(delegateDefaultDrmSessionManager.getOfflineLicenseKeySetId(), cachedKeySetId))
                        delegateDefaultDrmSessionManager.setMode(MODE_QUERY, cachedKeySetId);

                }
            } catch (DrmSession.DrmSessionException e) {
                Log.e(TAG, "Error renewing drm keys");
                //TODO ERASE whatever is here.
                cachedKeySetId = null;
                removeKeySetId(schemeInitD);
            }

        }

        if (cachedKeySetId==null){
            Log.i(TAG,"No cached key set found ");
            delegateDefaultDrmSessionManager.setMode(MODE_DOWNLOAD,null);
        }
        DrmSession<T> tDrmSession = delegateDefaultDrmSessionManager.acquireSession(playbackLooper, drmInitData);
        Log.i(TAG,"Acquire license request is done");
        return tDrmSession;
    }

    @Override
    public void releaseSession(DrmSession<T> drmSession) {
        pending.set(false);
        delegateDefaultDrmSessionManager.releaseSession(drmSession);
    }

    public void storeKeySetId(byte[] initData, byte[] keySetId) {
        String encodedInitData = Base64.encodeToString(initData, Base64.NO_WRAP);
        String encodedKeySetId = Base64.encodeToString(keySetId, Base64.NO_WRAP);
        drmkeys.edit()
                .putString(encodedInitData, encodedKeySetId)
                .apply();
    }
    public void removeKeySetId (byte[] initData) {
        String encodedInitData = Base64.encodeToString(initData, Base64.NO_WRAP);
        drmkeys.edit()
                .remove(encodedInitData)
                .apply();
    }

    public byte[] loadKeySetId(byte[] initData) {
        String encodedInitData = Base64.encodeToString(initData, Base64.NO_WRAP);
        String encodedKeySetId = drmkeys.getString(encodedInitData, null);
        if (encodedKeySetId == null) return null;
        return Base64.decode(encodedKeySetId, 0);
    }

}
