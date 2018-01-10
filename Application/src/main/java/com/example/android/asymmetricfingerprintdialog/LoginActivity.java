package com.example.android.asymmetricfingerprintdialog;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.util.jar.Manifest;

/**
 * Created by anildeshpande on 1/2/17.
 */

public class LoginActivity extends Activity implements FingerprintAuthenticationDialogFragment.FingerprintAuthenticationListener {

    private static final String TAG=LoginActivity.class.getSimpleName();

    private static final String DIALOG_FRAGMENT_TAG = "myFragment";
    /** Alias for our key in the Android Key Store */
    public static final String KEY_NAME = "my_key";

    private EditText editTextUsername, editTextPassword;
    private Button buttonLogin,buttonUseFingerprint;

    private FingerprintModule fingerprintModule;

    private KeyguardManager mKeyguardManager;
    private FingerprintManager mFingerprintManager;
    private FingerprintAuthenticationDialogFragment mFragment;
    private KeyStore mKeyStore;
    private KeyPairGenerator mKeyPairGenerator;
    private Signature mSignature;
    private SharedPreferences mSharedPreferences;

    private String userName,password;

    boolean isKeyGaurdSet=true;
    boolean areFingerPrintsEnrolled=true;
    boolean isHardwaredetected=false;

    boolean didFingerprintSanityCheckSucceed;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.login_layout);

        editTextUsername=(EditText)findViewById(R.id.editTextUsername);
        editTextPassword=(EditText)findViewById(R.id.editTextPassword);
        buttonUseFingerprint=(Button)findViewById(R.id.buttonUseFingerPrint);
        buttonUseFingerprint.setEnabled(false);
        buttonUseFingerprint.setVisibility(View.INVISIBLE);

        buttonLogin=(Button)findViewById(R.id.buttonLogin);
        mSharedPreferences=getSharedPreferences("usernamesaved",MODE_PRIVATE);

        if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.M){
            fingerprintModule=((InjectedApplication)getApplication()).getFingerprintModule();
            mKeyguardManager=fingerprintModule.getKeyguardManager(this);
            mFingerprintManager=fingerprintModule.getFingerprintManager(this);
            mKeyStore=fingerprintModule.getKeystore();
            mKeyPairGenerator=fingerprintModule.getKeyPairGenerator();
            mSignature=fingerprintModule.getSignature(mKeyStore);


            buttonUseFingerprint.setEnabled(true);
            buttonUseFingerprint.setVisibility(View.VISIBLE);


            mFragment=new FingerprintAuthenticationDialogFragment();
            mFragment.setFingerprintAuthenticationListener(this);

            buttonUseFingerprint.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if(didFingerprintSanityCheckSucceed){
                        triggerFingerScanDialog();
                    }else{
                        Toast.makeText(getApplicationContext(),"Can not use Fingerprint",Toast.LENGTH_SHORT).show();
                    }

                }
            });

            sanityCheckForAPIVersionSpecifFingerprintBasedFlow();
        }

        buttonLogin.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Set up the crypto object for later. The object will be authenticated by use
                // of the fingerprint.
                userName=editTextPassword.getText().toString();
                password=editTextPassword.getText().toString();

                if(userName.equals("anil") && password.equals("anil")){
                    if(userName.length()>0 && !userName.equals("")){
                        SharedPreferences.Editor editor=mSharedPreferences.edit();
                        editor.putString("USERNAME",userName);
                        editor.putString(userName,password);
                        editor.commit();
                    }
                    navigateToNextActivity();
                }
            }
        });





    }

    @TargetApi(23)
    private void sanityCheckForAPIVersionSpecifFingerprintBasedFlow(){

        ActivityCompat.requestPermissions(this,new String[]{android.Manifest.permission.USE_FINGERPRINT},0);

        if(ActivityCompat.checkSelfPermission(getApplicationContext(), android.Manifest.permission.USE_FINGERPRINT)==PackageManager.PERMISSION_GRANTED){
            if(mFingerprintManager.isHardwareDetected()){
                isHardwaredetected=true;
            }
        }

        if(isHardwaredetected){
            if (!mKeyguardManager.isKeyguardSecure()) {
                // Show a message that the user hasn't set up a fingerprint or lock screen.
            /*Toast.makeText(this,
                    "Secure lock screen hasn't set up.\n"
                            + "Go to 'Settings -> Security -> Fingerprint' to set up a fingerprint",
                    Toast.LENGTH_LONG).show();*/
                isKeyGaurdSet=false;

            }
            //noinspection ResourceType
            if (!mFingerprintManager.hasEnrolledFingerprints()) {
                // This happens when no fingerprints are registered.
            /*Toast.makeText(this,
                    "Go to 'Settings -> Security -> Fingerprint' and register at least one fingerprint",
                    Toast.LENGTH_LONG).show();*/
                areFingerPrintsEnrolled=false;

            }
        }

        if(isHardwaredetected && isKeyGaurdSet && areFingerPrintsEnrolled){
            didFingerprintSanityCheckSucceed=true;
            createKeyPair();
        }else{
            didFingerprintSanityCheckSucceed=false;
        }

    }

    @TargetApi(Build.VERSION_CODES.M)
    public void createKeyPair() {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            mKeyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(KEY_NAME,
                            KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            // Require the user to authenticate with a fingerprint to authorize
                            // every use of the private key
                            .setUserAuthenticationRequired(true)
                            .build());
            mKeyPairGenerator.generateKeyPair();
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private boolean initSignature() {
        try {
            mKeyStore.load(null);
            PrivateKey key = (PrivateKey) mKeyStore.getKey(KEY_NAME, null);
            mSignature.initSign(key);
            return true;
        } catch (InvalidKeyException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    public void onPurchased(byte[] signature) {
        showConfirmation(signature);
    }

    public void onPurchaseFailed() {
        Toast.makeText(this, R.string.purchase_fail, Toast.LENGTH_SHORT).show();
    }

    private void showConfirmation(byte[] encrypted) {
        /*findViewById(R.id.confirmation_message).setVisibility(View.VISIBLE);
        if (encrypted != null) {
            TextView v = (TextView) findViewById(R.id.encrypted_message);
            v.setVisibility(View.VISIBLE);
            v.setText(Base64.encodeToString(encrypted, 0 *//* flags *//*));
        }*/
        navigateToNextActivity();
    }

    private void navigateToNextActivity(){
        Intent intent=new Intent(this,AfterLoginActivity.class);
        startActivity(intent);
    }

    private String getUsernameFromSharedPreference(){
        String userName=null;
        if(mSharedPreferences!=null){
            userName=mSharedPreferences.getString("USERNAME","NA");
        }

        return userName;
    }

    private String getPasswordFromSharedPrferences(){
        String passowrd=null;
        if(mSharedPreferences!=null){
            passowrd=mSharedPreferences.getString(getUsernameFromSharedPreference(),"NA");
        }
        return passowrd;
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void triggerFingerScanDialog(){
        if (initSignature()) {

            // Show the fingerprint dialog. The user has the option to use the fingerprint with
            // crypto, or you can fall back to using a server-side verified password.
            mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mSignature));
            boolean useFingerprintPreference = mSharedPreferences
                    .getBoolean(getString(R.string.use_fingerprint_to_authenticate_key),
                            true);
            if (useFingerprintPreference) {
                mFragment.setStage(
                        FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);
            } else {
                mFragment.setStage(
                        FingerprintAuthenticationDialogFragment.Stage.PASSWORD);
            }
            mFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
        } else {
            // This happens if the lock screen has been disabled or or a fingerprint got
            // enrolled. Thus show the dialog to authenticate with their password first
            // and ask the user if they want to authenticate with fingerprints in the
            // future
            mFragment.setStage(
                    FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
            mFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);

        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        userName=getUsernameFromSharedPreference();
        password=getPasswordFromSharedPrferences();
        editTextUsername.setText(userName);
    }

    @Override
    public void onAuthenticationResult(Bundle bundle) {
        final int result=bundle.getInt(FingerprintAuthenticationDialogFragment.FingerprintAuthenticationListener.AUTHENTICATION_RESULT, FingerprintAuthenticationDialogFragment.FingerprintAuthenticationListener.USE_PASSWORD);
        switch (result){
            case FINGER_AUTH_SUCCESS: navigateToNextActivity(); break;
            case USE_PASSWORD: editTextPassword.requestFocus();   break;
            default: break;
        }
    }
}
