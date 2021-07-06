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

package org.keycloak.services.resources.admin;

import com.google.common.collect.Streams;
import org.apache.commons.io.IOUtils;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.plugins.providers.multipart.InputPart;
import org.jboss.resteasy.plugins.providers.multipart.MultipartFormDataInput;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.models.utils.StripSecretsUtils;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.stream.Stream;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;

import org.keycloak.utils.ReservedCharValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * @resource Identity Providers
 * @author Pedro Igor
 */
public class IdentityProvidersResource {

    private final RealmModel realm;
    private final KeycloakSession session;
    private AdminPermissionEvaluator auth;
    private AdminEventBuilder adminEvent;

    public IdentityProvidersResource(RealmModel realm, KeycloakSession session, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.realm = realm;
        this.session = session;
        this.auth = auth;
        this.adminEvent = adminEvent.resource(ResourceType.IDENTITY_PROVIDER);
    }

    /**
     * Get identity providers
     *
     * @param providerId Provider id
     * @return
     */
    @Path("/providers/{provider_id}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Response getIdentityProviders(@PathParam("provider_id") String providerId) {
        this.auth.realm().requireViewIdentityProviders();
        IdentityProviderFactory providerFactory = getProviderFactorytById(providerId);
        if (providerFactory != null) {
            return Response.ok(providerFactory).build();
        }
        return Response.status(BAD_REQUEST).build();
    }

    /**
     * Import identity provider from uploaded JSON file
     *
     * @param input
     * @return
     * @throws IOException
     */
    @POST
    @Path("import-config")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, String> importFrom(MultipartFormDataInput input) throws IOException {
        this.auth.realm().requireManageIdentityProviders();
        Map<String, List<InputPart>> formDataMap = input.getFormDataMap();

        if (!(formDataMap.containsKey("providerId") && formDataMap.containsKey("file"))) {
            throw new BadRequestException();
        }
        String providerId = formDataMap.get("providerId").get(0).getBodyAsString();
        InputPart file = formDataMap.get("file").get(0);
        InputStream inputStream = file.getBody(InputStream.class, null);

        if(providerId.equalsIgnoreCase("oidc")) {

            String filename = extractFilenameFromHeaders(file.getHeaders());

            java.nio.file.Files.copy(
                    file.getBody(InputStream.class, null),
                    new File(filename).toPath(),
                    StandardCopyOption.REPLACE_EXISTING);
        }

        IdentityProviderFactory providerFactory = getProviderFactorytById(providerId);

        Map<String, String> config;
        if (file.getMediaType().toString().contains("xml")) {
            config = parseXmlConfig(inputStream);
        }
        else if (file.getMediaType().toString().contains("octet-stream")) {
            config = parseBinaryConfig(inputStream);
        } else {
            config = providerFactory.parseConfig(session, inputStream);
        }

        return config;
    }

    private Map<String, String> parseXmlConfig(InputStream inputStream) {

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(inputStream);
            doc.getDocumentElement().normalize();

            Element element = doc.getDocumentElement();

            OIDCIdentityProviderConfig config = new OIDCIdentityProviderConfig();
            config.setIssuer(element.getElementsByTagName("issuer").item(0).getTextContent());
            config.setLogoutUrl(element.getElementsByTagName("end_session_endpoint").item(0).getTextContent());
            config.setAuthorizationUrl(element.getElementsByTagName("authorization_endpoint").item(0).getTextContent());
            config.setTokenUrl(element.getElementsByTagName("token_endpoint").item(0).getTextContent());
            config.setUserInfoUrl(element.getElementsByTagName("userinfo_endpoint").item(0).getTextContent());
            if (element.getElementsByTagName("jwks_uri").item(0).getTextContent() != null) {
                config.setValidateSignature(true);
                config.setUseJwksUrl(true);
                config.setJwksUrl(element.getElementsByTagName("jwks_uri").item(0).getTextContent());
            }
            return config.getConfig();
        } catch (ParserConfigurationException e) {
            throw new RuntimeException("ParserConfigurationException was thrown: " + e.getMessage());
        } catch (SAXException e) {
            throw new RuntimeException("SAXException was thrown: " + e.getMessage());
        } catch (IOException e) {
            throw new RuntimeException("IOException was thrown. IOException occurred, XXE may still possible: " + e.getMessage());
        }
    }

    private Map<String, String> parseBinaryConfig(InputStream inputStream) {

        OIDCConfigurationRepresentation rep;

        try {
            byte[] bytes = IOUtils.toByteArray(inputStream);

            ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(bytes));

            rep = (OIDCConfigurationRepresentation) stream.readObject();

        } catch(Exception e) {
            throw new RuntimeException("failed to load openid connect metadata", e);
        }

        OIDCIdentityProviderConfig config = new OIDCIdentityProviderConfig();
        config.setIssuer(rep.getIssuer());
        config.setLogoutUrl(rep.getLogoutEndpoint());
        config.setAuthorizationUrl(rep.getAuthorizationEndpoint());
        config.setTokenUrl(rep.getTokenEndpoint());
        config.setUserInfoUrl(rep.getUserinfoEndpoint());
        if (rep.getJwksUri() != null) {
            config.setValidateSignature(true);
            config.setUseJwksUrl(true);
            config.setJwksUrl(rep.getJwksUri());
        }
        return config.getConfig();
    }

    private String extractFilenameFromHeaders(MultivaluedMap<String, String> headers) {
        List<String> contentDisposition = headers.get("Content-Disposition");

        for(String element : contentDisposition) {
            if(element.contains("filename")) {

                String[] kvPairs = element.split(";");

                for(String kvPair: kvPairs) {
                    if(kvPair.contains("filename")) {
                        String[] kv = kvPair.split("=");
                        String key = kv[0];
                        String value = kv[1];

                        if(key.contains("filename")) {
                            return value.replace("\"", "").replace(" ", "");
                        }
                    }
                }
            }
        }

        return "";
    }

    /**
     * Import identity provider from JSON body
     *
     * @param data JSON body
     * @return
     * @throws IOException
     */
    @POST
    @Path("import-config")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, String> importFrom(Map<String, Object> data) throws IOException {
        this.auth.realm().requireManageIdentityProviders();
        if (!(data.containsKey("providerId") && data.containsKey("fromUrl"))) {
            throw new BadRequestException();
        }
        
        ReservedCharValidator.validate((String)data.get("alias"));
        
        String providerId = data.get("providerId").toString();
        String from = data.get("fromUrl").toString();
        System.out.println("************************");
        System.out.println("1--" + from + "--");
        InputStream inputStream = session.getProvider(HttpClientProvider.class).get(from);
        System.out.println("2--" + inputStream.toString() + "--");
        StringBuilder textBuilder = new StringBuilder();
        try (Reader reader = new BufferedReader(new InputStreamReader
                (inputStream, Charset.forName(StandardCharsets.UTF_8.name())))) {
            int c = 0;
            while ((c = reader.read()) != -1) {
                textBuilder.append((char) c);
            }
        }
        System.out.println("3--" + textBuilder.toString() + "--");
        try {
            IdentityProviderFactory providerFactory = getProviderFactorytById(providerId);
            Map<String, String> config;
            config = providerFactory.parseConfig(session, inputStream);
            return config;
        } finally {
            try {
                inputStream.close();
            } catch (IOException e) {
            }
        }
    }

    /**
     * Get identity providers
     *
     * @return
     */
    @GET
    @Path("instances")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Stream<IdentityProviderRepresentation> getIdentityProviders() {
        this.auth.realm().requireViewIdentityProviders();

        return realm.getIdentityProvidersStream()
                .map(provider -> StripSecretsUtils.strip(ModelToRepresentation.toRepresentation(realm, provider)));
    }

    /**
     * Create a new identity provider
     *
     * @param representation JSON body
     * @return
     */
    @POST
    @Path("instances")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response create(IdentityProviderRepresentation representation) {
        this.auth.realm().requireManageIdentityProviders();

        ReservedCharValidator.validate(representation.getAlias());
        
        try {
            IdentityProviderModel identityProvider = RepresentationToModel.toModel(realm, representation, session);
            this.realm.addIdentityProvider(identityProvider);

            representation.setInternalId(identityProvider.getInternalId());
            adminEvent.operation(OperationType.CREATE).resourcePath(session.getContext().getUri(), identityProvider.getAlias())
                    .representation(StripSecretsUtils.strip(representation)).success();
            
            return Response.created(session.getContext().getUri().getAbsolutePathBuilder().path(representation.getAlias()).build()).build();
        } catch (IllegalArgumentException e) {
            String message = e.getMessage();
            
            if (message == null) {
                message = "Invalid request";
            }
            
            return ErrorResponse.error(message, BAD_REQUEST);
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Identity Provider " + representation.getAlias() + " already exists");
        }
    }

    @Path("instances/{alias}")
    public IdentityProviderResource getIdentityProvider(@PathParam("alias") String alias) {
        this.auth.realm().requireViewIdentityProviders();
        IdentityProviderModel identityProviderModel =  this.realm.getIdentityProvidersStream()
                .filter(p -> Objects.equals(p.getAlias(), alias) || Objects.equals(p.getInternalId(), alias))
                .findFirst().orElse(null);

        IdentityProviderResource identityProviderResource = new IdentityProviderResource(this.auth, realm, session, identityProviderModel, adminEvent);
        ResteasyProviderFactory.getInstance().injectProperties(identityProviderResource);
        
        return identityProviderResource;
    }

    private IdentityProviderFactory getProviderFactorytById(String providerId) {
        return getProviderFactories()
                .filter(providerFactory -> Objects.equals(providerId, providerFactory.getId()))
                .map(IdentityProviderFactory.class::cast)
                .findFirst()
                .orElse(null);
    }

    private Stream<ProviderFactory> getProviderFactories() {
        return Streams.concat(session.getKeycloakSessionFactory().getProviderFactoriesStream(IdentityProvider.class),
                session.getKeycloakSessionFactory().getProviderFactoriesStream(SocialIdentityProvider.class));
    }
}
