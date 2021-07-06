/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.services.clientpolicy.condition;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyVote;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public class ClientAccessTypeCondition implements ClientPolicyConditionProvider<ClientAccessTypeCondition.Configuration> {

    private static final Logger logger = Logger.getLogger(ClientAccessTypeCondition.class);

    // to avoid null configuration, use vacant new instance to indicate that there is no configuration set up.
    private Configuration configuration = new Configuration();
    private final KeycloakSession session;

    public ClientAccessTypeCondition(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void setupConfiguration(Configuration config) {
        this.configuration = config;
    }

    @Override
    public Class<Configuration> getConditionConfigurationClass() {
        return Configuration.class;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Configuration extends ClientPolicyConditionConfiguration {
        @JsonProperty("is-negative-logic")
        protected Boolean negativeLogic;

        public Boolean isNegativeLogic() {
            return negativeLogic;
        }

        public void setNegativeLogic(Boolean negativeLogic) {
            this.negativeLogic = negativeLogic;
        }

        protected List<String> type;

        public List<String> getType() {
            return type;
        }

        public void setType(List<String> type) {
            this.type = type;
        }
    }

    @Override
    public boolean isNegativeLogic() {
        return Optional.ofNullable(this.configuration.isNegativeLogic()).orElse(Boolean.FALSE).booleanValue();
    }

    @Override
    public String getProviderId() {
        return ClientAccessTypeConditionFactory.PROVIDER_ID;
    }

    @Override
    public ClientPolicyVote applyPolicy(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
            case AUTHORIZATION_REQUEST:
            case TOKEN_REQUEST:
            case TOKEN_REFRESH:
            case TOKEN_REVOKE:
            case TOKEN_INTROSPECT:
            case USERINFO_REQUEST:
            case LOGOUT_REQUEST:
                if (isClientAccessTypeMatched()) return ClientPolicyVote.YES;
                return ClientPolicyVote.NO;
            default:
                return ClientPolicyVote.ABSTAIN;
        }
    }

    private String getClientAccessType() {
        ClientModel client = session.getContext().getClient();
        if (client == null) return null;

        if (client.isPublicClient()) return ClientAccessTypeConditionFactory.TYPE_PUBLIC;
        if (client.isBearerOnly()) return ClientAccessTypeConditionFactory.TYPE_BEARERONLY;
        else return ClientAccessTypeConditionFactory.TYPE_CONFIDENTIAL;
    }

    private boolean isClientAccessTypeMatched() {
        final String accessType = getClientAccessType();
        if (accessType == null) return false;

        List<String> expectedAccessTypes = Optional.ofNullable(configuration.getType()).orElse(Collections.emptyList());

        if (logger.isTraceEnabled()) {
            logger.tracev("accessType = {0}", accessType);
            expectedAccessTypes.stream().forEach(i -> logger.tracev("expected accessType = {0}", i));
        }

        return expectedAccessTypes.stream().anyMatch(i -> i.equals(accessType));
    }

}
