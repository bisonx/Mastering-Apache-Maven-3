package jose;

import java.security.*;
import java.security.interfaces.*;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;

public class JWTBuilder {

    public static void main(String[] args) throws ParseException, JOSEException,
            NoSuchAlgorithmException {

        decryptJWT();

    }

    public static void decryptJWT() throws NoSuchAlgorithmException, JOSEException, ParseException {

        // generate private/public key pair.
        KeyPair keyPair = generateKeyPair();

        // get the private key - used to decrypt the message.
        PrivateKey privateKey = keyPair.getPrivate();

        // get the public key - used to encrypt the message.
        PublicKey publicKey = keyPair.getPublic();

        // get encrypted JWT in base64-encoded text.
        String jwtInText = buildEncryptedJWT(publicKey);

        // create a decrypter.
        JWEDecrypter decrypter = new RSADecrypter((RSAPrivateKey) privateKey);

        // create the encrypted JWT with the base64-encoded text.
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(jwtInText);

        // decrypt the JWT.
        encryptedJWT.decrypt(decrypter);

        // print the value of JWT header.
        System.out.println("JWE Header:" + encryptedJWT.getHeader());

        // JWE content encryption key.
        System.out.println("JWE Content Encryption Key: " + encryptedJWT.getEncryptedKey());

        // initialization vector.
        System.out.println("Initialization Vector: " + encryptedJWT.getInitializationVector());

        // ciphertext.
        System.out.println("Ciphertext : " + encryptedJWT.getCipherText());

        // authentication tag.
        System.out.println("Authentication Tag: " + encryptedJWT.getAuthenticationTag());

        // print the value of JWT body.
        System.out.println("Decrypted Payload: " + encryptedJWT.getPayload());

    }

    public static String buildEncryptedJWT(PublicKey publicKey) throws JOSEException {

        // create a claim set.
        JWTClaimsSet jwtClaims = new JWTClaimsSet();

        // set the value of the issuer.
        jwtClaims.setIssuer("https://apress.com");

        // set the subject value - JWT belongs to the subject.
        jwtClaims.setSubject("john");

        // set values for audience restriction.
        List<String> aud = new ArrayList<String>();
        aud.add("https://app1.foo.com");
        aud.add("https://app2.foo.com");
        jwtClaims.setAudience(aud);

        // expiration time set to 10 minutes.
        jwtClaims.setExpirationTime(new Date(new Date().getTime() + 1000 * 60 * 10));

        Date currentTime = new Date();

        // set the valid from time to current time.
        jwtClaims.setNotBeforeTime(currentTime);

        // set issued time to current time.
        jwtClaims.setIssueTime(currentTime);

        // set a generated UUID as the JWT identifier.
        jwtClaims.setJWTID(UUID.randomUUID().toString());

        // create JWE header with RSA-OAEP and AES/GCM.
        JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);

        // create encrypter with the RSA public key.
        JWEEncrypter encrypter = new RSAEncrypter((RSAPublicKey) publicKey);

        // create the signed JWT with the JWS header and the JWT body.
        EncryptedJWT encryptedJWT = new EncryptedJWT(jweHeader, jwtClaims);

        // encrypt the JWT.
        encryptedJWT.encrypt(encrypter);

        // serialize into base64-encoded text.
        String jwtInText = encryptedJWT.serialize();

        // print the value of the JWT.
        System.out.println(jwtInText);

        return jwtInText;
    }

    public static boolean isValidRsaSha256Signature() throws NoSuchAlgorithmException,
            JOSEException, ParseException {

        // generate private/public key pair.
        KeyPair keyPair = generateKeyPair();

        // get the private key - used to sign the message.
        PrivateKey privateKey = keyPair.getPrivate();

        // / get public key - used to verify the message signature.
        PublicKey publicKey = keyPair.getPublic();

        // get signed JWT in base64-encoded text.
        String jwtInText = buildRsaSha256SignedJWT(privateKey);

        // create verifier with the provider shared secret.
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);

        // create the signed JWT with the base64-encoded text.
        SignedJWT signedJWT = SignedJWT.parse(jwtInText);

        // verify the signature of the JWT.
        boolean isValid = signedJWT.verify(verifier);

        if (isValid) {
            System.out.println("valid JWT signature");
        } else {
            System.out.println("invalid JWT signature");
        }

        return isValid;
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {

        // instantiate KeyPaitGenerate with RSA algorithm.
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");

        // set the key size to 1024 bits.
        keyGenerator.initialize(1024);

        // generate and return private/public key pair.
        return keyGenerator.genKeyPair();
    }

    public static String buildRsaSha256SignedJWT(PrivateKey privateKey) throws JOSEException {

        // create a claim set.
        JWTClaimsSet jwtClaims = new JWTClaimsSet();

        // set the value of the issuer.
        jwtClaims.setIssuer("https://apress.com");

        // set the subject value - JWT belongs to the subject.
        jwtClaims.setSubject("john");

        // set values for audience restriction.
        List<String> aud = new ArrayList<String>();
        aud.add("https://app1.foo.com");
        aud.add("https://app2.foo.com");
        jwtClaims.setAudience(aud);

        // expiration time set to 10 minutes.
        jwtClaims.setExpirationTime(new Date(new Date().getTime() + 1000 * 60 * 10));

        Date currentTime = new Date();

        // set the valid from time to current time.
        jwtClaims.setNotBeforeTime(currentTime);

        // set issued time to current time.
        jwtClaims.setIssueTime(currentTime);

        // set a generated UUID as the JWT identifier.
        jwtClaims.setJWTID(UUID.randomUUID().toString());

        // create JWS header with RSA-SHA256 algorithm.
        JWSHeader jswHeader = new JWSHeader(JWSAlgorithm.RS256);

        // create signer with the RSA private key..
        JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);

        // create the signed JWT with the JWS header and the JWT body.
        SignedJWT signedJWT = new SignedJWT(jswHeader, jwtClaims);

        // sign the JWT with HMAC-SHA256.
        signedJWT.sign(signer);

        // serialize into base64-encoded text.
        String jwtInText = signedJWT.serialize();

        // print the value of the JWT.
        System.out.println(jwtInText);

        return jwtInText;
    }

    public static boolean isValidHmacSha256Signature() throws JOSEException, ParseException {

        String sharedSecretString = "mysecretkey";

        // get signed JWT in base64-encoded text.
        String jwtInText = buildHmacSha256SignedJWT(sharedSecretString);

        // create verifier with the provider shared secret.
        JWSVerifier verifier = new MACVerifier(sharedSecretString);

        // create the signed JWT with the base64-encoded text.
        SignedJWT signedJWT = SignedJWT.parse(jwtInText);

        // verify the signature of the JWT.
        boolean isValid = signedJWT.verify(verifier);

        if (isValid) {
            System.out.println("valid JWT signature");
        } else {
            System.out.println("invalid JWT signature");
        }

        return isValid;
    }

    public static String buildHmacSha256SignedJWT(String sharedSecretString) throws JOSEException {

        // create a claim set.
        JWTClaimsSet jwtClaims = new JWTClaimsSet();

        // set the value of the issuer.
        jwtClaims.setIssuer("https://apress.com");

        // set the subject value - JWT belongs to the subject.
        jwtClaims.setSubject("john");

        // set values for audience restriction.
        List<String> aud = new ArrayList<String>();
        aud.add("https://app1.foo.com");
        aud.add("https://app2.foo.com");
        jwtClaims.setAudience(aud);

        // expiration time set to 10 minutes.
        jwtClaims.setExpirationTime(new Date(new Date().getTime() + 1000 * 60 * 10));

        Date currentTime = new Date();

        // set the valid from time to current time.
        jwtClaims.setNotBeforeTime(currentTime);

        // set issued time to current time.
        jwtClaims.setIssueTime(currentTime);

        // set a generated UUID as the JWT identifier.
        jwtClaims.setJWTID(UUID.randomUUID().toString());

        // create JWS header with HMAC-SHA256 algorithm.
        JWSHeader jswHeader = new JWSHeader(JWSAlgorithm.HS256);

        // create signer with the provider shared secret.
        JWSSigner signer = new MACSigner(sharedSecretString);

        // create the signed JWT with the JWS header and the JWT body.
        SignedJWT signedJWT = new SignedJWT(jswHeader, jwtClaims);

        // sign the JWT with HMAC-SHA256.
        signedJWT.sign(signer);

        // serialize into base64-encoded text.
        String jwtInText = signedJWT.serialize();

        // print the value of the JWT.
        System.out.println(jwtInText);

        return jwtInText;
    }

    public static String buildPlainJWT() {

        // create a claim set.
        JWTClaimsSet jwtClaims = new JWTClaimsSet();

        // set the value of the issuer.
        jwtClaims.setIssuer("https://apress.com");

        // set the subject value - JWT belongs to the subject.
        jwtClaims.setSubject("john");

        // set values for audience restriction.
        List<String> aud = new ArrayList<String>();
        aud.add("https://app1.foo.com");
        aud.add("https://app2.foo.com");
        jwtClaims.setAudience(aud);

        // expiration time set to 10 minutes.
        jwtClaims.setExpirationTime(new Date(new Date().getTime() + 1000 * 60 * 10));

        Date currentTime = new Date();

        // set the valid from time to current time.
        jwtClaims.setNotBeforeTime(currentTime);

        // set issued time to current time.
        jwtClaims.setIssueTime(currentTime);

        // set a generated UUID as the JWT identifier.
        jwtClaims.setJWTID(UUID.randomUUID().toString());

        // create plain JWT with the JWT claims.
        PlainJWT plainJwt = new PlainJWT(jwtClaims);

        String jwtInText = plainJwt.serialize();

        // print the value of the JWT.
        System.out.println(plainJwt.serialize());

        return jwtInText;
    }

    public static void parsePlainJWT() throws ParseException {

        // get JWT in base64-encoded text.
        String jwtInText = buildPlainJWT();

        // build a plain JWT from the bade64 encoded text.
        PlainJWT plainJwt = PlainJWT.parse(jwtInText);

        // print the JWT header in JSON.
        System.out.println(plainJwt.getHeader().toString());

        // print JWT body in JSON.
        System.out.println(plainJwt.getPayload().toString());

    }

}
