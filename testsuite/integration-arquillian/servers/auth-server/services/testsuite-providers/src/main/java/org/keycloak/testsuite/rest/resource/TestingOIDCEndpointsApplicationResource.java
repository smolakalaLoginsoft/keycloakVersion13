/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.rest.resource;

import org.jboss.resteasy.annotations.cache.NoCache;
import javax.ws.rs.BadRequestException;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.PemUtils;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.ServerECDSASignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.Constants;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.testsuite.rest.TestApplicationResourceProviderFactory;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TestingOIDCEndpointsApplicationResource {

    public static final String PRIVATE_KEY = "privateKey";
    public static final String PUBLIC_KEY = "publicKey";

    private final TestApplicationResourceProviderFactory.OIDCClientData clientData;

    public TestingOIDCEndpointsApplicationResource(TestApplicationResourceProviderFactory.OIDCClientData oidcClientData) {
        this.clientData = oidcClientData;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/generate-keys")
    @NoCache
    public Map<String, String> generateKeys(@QueryParam("jwaAlgorithm") String jwaAlgorithm) {
        try {
            KeyPair keyPair = null;
            KeyUse keyUse = KeyUse.SIG;
            if (jwaAlgorithm == null) jwaAlgorithm = Algorithm.RS256;
            String keyType = null;

            switch (jwaAlgorithm) {
                case Algorithm.RS256:
                case Algorithm.RS384:
                case Algorithm.RS512:
                case Algorithm.PS256:
                case Algorithm.PS384:
                case Algorithm.PS512:
                    keyType = KeyType.RSA;
                    keyPair = KeyUtils.generateRsaKeyPair(2048);
                    break;
                case Algorithm.ES256:
                    keyType = KeyType.EC;
                    keyPair = generateEcdsaKey("secp256r1");
                    break;
                case Algorithm.ES384:
                    keyType = KeyType.EC;
                    keyPair = generateEcdsaKey("secp384r1");
                    break;
                case Algorithm.ES512:
                    keyType = KeyType.EC;
                    keyPair = generateEcdsaKey("secp521r1");
                    break;
                case JWEConstants.RSA1_5:
                case JWEConstants.RSA_OAEP:
                case JWEConstants.RSA_OAEP_256:
                    // for JWE KEK Key Encryption
                    keyType = KeyType.RSA;
                    keyUse = KeyUse.ENC;
                    keyPair = KeyUtils.generateRsaKeyPair(2048);
                    break;
                default :
                    throw new RuntimeException("Unsupported signature algorithm");
            }

            clientData.setKeyPair(keyPair);
            clientData.setKeyType(keyType);
            clientData.setKeyAlgorithm(jwaAlgorithm);
            clientData.setKeyUse(keyUse);
        } catch (Exception e) {
            throw new BadRequestException("Error generating signing keypair", e);
        }
        return getKeysAsPem();
    }

    private KeyPair generateEcdsaKey(String ecDomainParamName) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        SecureRandom randomGen = SecureRandom.getInstance("SHA1PRNG");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(ecDomainParamName);
        keyGen.initialize(ecSpec, randomGen);
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/get-keys-as-pem")
    public Map<String, String> getKeysAsPem() {
        String privateKeyPem = PemUtils.encodeKey(clientData.getSigningKeyPair().getPrivate());
        String publicKeyPem = PemUtils.encodeKey(clientData.getSigningKeyPair().getPublic());

        Map<String, String> res = new HashMap<>();
        res.put(PRIVATE_KEY, privateKeyPem);
        res.put(PUBLIC_KEY, publicKeyPem);
        return res;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/get-keys-as-base64")
    public Map<String, String> getKeysAsBase64() {
        // It seems that PemUtils.decodePrivateKey, decodePublicKey can only treat RSA type keys, not EC type keys. Therefore, these are not used.
        String privateKeyPem = Base64.encodeBytes(clientData.getSigningKeyPair().getPrivate().getEncoded());
        String publicKeyPem = Base64.encodeBytes(clientData.getSigningKeyPair().getPublic().getEncoded());

        Map<String, String> res = new HashMap<>();
        res.put(PRIVATE_KEY, privateKeyPem);
        res.put(PUBLIC_KEY, publicKeyPem);
        return res;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/get-jwks")
    @NoCache
    public JSONWebKeySet getJwks() {
        JSONWebKeySet keySet = new JSONWebKeySet();
        KeyPair keyPair = clientData.getKeyPair();
        String keyAlgorithm = clientData.getKeyAlgorithm();
        String keyType = clientData.getKeyType();
        KeyUse keyUse = clientData.getKeyUse();

        if (keyPair == null || !isSupportedAlgorithm(keyAlgorithm)) {
            keySet.setKeys(new JWK[] {});
        } else if (KeyType.RSA.equals(keyType)) {
            keySet.setKeys(new JWK[] { JWKBuilder.create().algorithm(keyAlgorithm).rsa(keyPair.getPublic(), keyUse) });
        } else if (KeyType.EC.equals(keyType)) {
            keySet.setKeys(new JWK[] { JWKBuilder.create().algorithm(keyAlgorithm).ec(keyPair.getPublic()) });
        } else {
            keySet.setKeys(new JWK[] {});
        }

        return keySet;
        
    }


    @GET
    @Path("/set-oidc-request")
    @Produces(org.keycloak.utils.MediaType.APPLICATION_JWT)
    @NoCache
    public void setOIDCRequest(@QueryParam("realmName") String realmName, @QueryParam("clientId") String clientId,
                               @QueryParam("redirectUri") String redirectUri, @QueryParam("maxAge") String maxAge,
                               @QueryParam("jwaAlgorithm") String jwaAlgorithm) {

        Map<String, Object> oidcRequest = new HashMap<>();
        oidcRequest.put(OIDCLoginProtocol.CLIENT_ID_PARAM, clientId);
        oidcRequest.put(OIDCLoginProtocol.RESPONSE_TYPE_PARAM, OAuth2Constants.CODE);
        oidcRequest.put(OIDCLoginProtocol.REDIRECT_URI_PARAM, redirectUri);
        if (maxAge != null) {
            oidcRequest.put(OIDCLoginProtocol.MAX_AGE_PARAM, Integer.parseInt(maxAge));
        }

        setOidcRequest(oidcRequest, jwaAlgorithm);
    }

    @GET
    @Path("/register-oidc-request")
    @Produces(org.keycloak.utils.MediaType.APPLICATION_JWT)
    @NoCache
    public void registerOIDCRequest(@QueryParam("requestObject") String encodedRequestObject, @QueryParam("jwaAlgorithm") String jwaAlgorithm) {
        byte[] serializedRequestObject = Base64Url.decode(encodedRequestObject);
        AuthorizationEndpointRequestObject oidcRequest = null;
        try {
        	oidcRequest = JsonSerialization.readValue(serializedRequestObject, AuthorizationEndpointRequestObject.class);
        } catch (IOException e) {
            throw new BadRequestException("deserialize request object failed : " + e.getMessage());
        }

        setOidcRequest(oidcRequest, jwaAlgorithm);
    }

    private void setOidcRequest(Object oidcRequest, String jwaAlgorithm) {
        if (!isSupportedAlgorithm(jwaAlgorithm)) throw new BadRequestException("Unknown argument: " + jwaAlgorithm);

        if ("none".equals(jwaAlgorithm)) {
            clientData.setOidcRequest(new JWSBuilder().jsonContent(oidcRequest).none());
        } else  if (clientData.getSigningKeyPair() == null) {
            throw new BadRequestException("signing key not set");
        } else {
            PrivateKey privateKey = clientData.getSigningKeyPair().getPrivate();
            String kid = KeyUtils.createKeyId(clientData.getSigningKeyPair().getPublic());
            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setAlgorithm(clientData.getSigningKeyAlgorithm());
            keyWrapper.setKid(kid);
            keyWrapper.setPrivateKey(privateKey);
            SignatureSignerContext signer;
            switch (clientData.getSigningKeyAlgorithm()) {
                case Algorithm.ES256:
                case Algorithm.ES384:
                case Algorithm.ES512:
                    signer = new ServerECDSASignatureSignerContext(keyWrapper);
                    break;
                default:
                    signer = new AsymmetricSignatureSignerContext(keyWrapper);
            }
            clientData.setOidcRequest(new JWSBuilder().kid(kid).jsonContent(oidcRequest).sign(signer));
        }
    }

    private boolean isSupportedAlgorithm(String signingAlgorithm) {
        if (signingAlgorithm == null) return false;
        boolean ret = false;
        switch (signingAlgorithm) {
            case "none":
            case Algorithm.RS256:
            case Algorithm.RS384:
            case Algorithm.RS512:
            case Algorithm.PS256:
            case Algorithm.PS384:
            case Algorithm.PS512:
            case Algorithm.ES256:
            case Algorithm.ES384:
            case Algorithm.ES512:
            case JWEConstants.RSA1_5:
            case JWEConstants.RSA_OAEP:
            case JWEConstants.RSA_OAEP_256:
                ret = true;
        }
        return ret;
    }

    @GET
    @Path("/get-oidc-request")
    @Produces(org.keycloak.utils.MediaType.APPLICATION_JWT)
    @NoCache
    public String getOIDCRequest() {
        return clientData.getOidcRequest();
    }

    @GET
    @Path("/set-sector-identifier-redirect-uris")
    @Produces(MediaType.APPLICATION_JSON)
    public void setSectorIdentifierRedirectUris(@QueryParam("redirectUris") List<String> redirectUris) {
        clientData.setSectorIdentifierRedirectUris(new ArrayList<>());
        clientData.getSectorIdentifierRedirectUris().addAll(redirectUris);
    }

    @GET
    @Path("/get-sector-identifier-redirect-uris")
    @Produces(MediaType.APPLICATION_JSON)
    public List<String> getSectorIdentifierRedirectUris() {
        return clientData.getSectorIdentifierRedirectUris();
    }

    public static class AuthorizationEndpointRequestObject extends JsonWebToken {

        @JsonProperty(OIDCLoginProtocol.CLIENT_ID_PARAM)
        String clientId;

        @JsonProperty(OIDCLoginProtocol.RESPONSE_TYPE_PARAM)
        String responseType;

        @JsonProperty(OIDCLoginProtocol.RESPONSE_MODE_PARAM)
        String responseMode;

        @JsonProperty(OIDCLoginProtocol.REDIRECT_URI_PARAM)
        String redirectUriParam;

        @JsonProperty(OIDCLoginProtocol.STATE_PARAM)
        String state;

        @JsonProperty(OIDCLoginProtocol.SCOPE_PARAM)
        String scope;

        @JsonProperty(OIDCLoginProtocol.LOGIN_HINT_PARAM)
        String loginHint;

        @JsonProperty(OIDCLoginProtocol.PROMPT_PARAM)
        String prompt;

        @JsonProperty(OIDCLoginProtocol.NONCE_PARAM)
        String nonce;

        Integer max_age;

        @JsonProperty(OIDCLoginProtocol.UI_LOCALES_PARAM)
        String uiLocales;

        @JsonProperty(OIDCLoginProtocol.ACR_PARAM)
        String acr;

        @JsonProperty(OAuth2Constants.DISPLAY)
        String display;

        @JsonProperty(OIDCLoginProtocol.CODE_CHALLENGE_PARAM)
        String codeChallenge;

        @JsonProperty(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM)
        String codeChallengeMethod;

        @JsonProperty(AdapterConstants.KC_IDP_HINT)
        String idpHint;

        @JsonProperty(Constants.KC_ACTION)
        String action;

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId =  clientId;
        }

        public String getResponseType() {
            return responseType;
        }

        public void setResponseType(String responseType) {
            this.responseType = responseType;
        }

        public String getResponseMode() {
            return responseMode;
        }

        public void setResponseMode(String responseMode) {
            this.responseMode = responseMode;
        }

        public String getRedirectUriParam() {
            return redirectUriParam;
        }

        public void setRedirectUriParam(String redirectUriParam) {
            this.redirectUriParam = redirectUriParam;
        }

        public String getState() {
            return state;
        }

        public void setState(String state) {
            this.state = state;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public String getLoginHint() {
            return loginHint;
        }

        public void setLoginHint(String loginHint) {
            this.loginHint = loginHint;
        }

        public String getPrompt() {
            return prompt;
        }

        public void setPrompt(String prompt) {
            this.prompt = prompt;
        }

        public String getNonce() {
            return nonce;
        }

        public void getNonce(String nonce) {
            this.nonce = nonce;
        }

        public Integer getMax_age() {
            return max_age;
        }

        public void setMax_age(Integer max_age) {
            this.max_age = max_age;
        }

        public String getUiLocales() {
            return uiLocales;
        }

        public void setUiLocales(String uiLocales) {
            this.uiLocales = uiLocales;
        }

        public String getAcr() {
            return acr;
        }

        public void setAcr(String acr) {
            this.acr = acr;
        }

        public String getCodeChallenge() {
            return codeChallenge;
        }

        public void setCodeChallenge(String codeChallenge) {
            this.codeChallenge = codeChallenge;
        }

        public String getCodeChallengeMethod() {
            return codeChallengeMethod;
        }

        public void setCodeChallengeMethod(String codeChallengeMethod) {
            this.codeChallengeMethod = codeChallengeMethod;
        }

        public String getDisplay() {
            return display;
        }

        public void setDisplay(String display) {
            this.display = display;
        }

        public String getIdpHint() {
            return idpHint;
        }

        public void setIdpHint(String idpHint) {
            this.idpHint = idpHint;
        }

        public String getAction() {
            return action;
        }

        public void setAction(String action) {
            this.action = action;
        }

    }
}
