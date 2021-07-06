/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.models.map.client;

import org.keycloak.models.ClientModel;
import org.keycloak.models.map.common.AbstractMapProviderFactory;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.ClientProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleContainerModel.RoleRemovedEvent;
import org.keycloak.models.RoleModel;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.keycloak.models.map.storage.MapStorageProvider;
import org.keycloak.models.map.storage.MapStorage;
import org.keycloak.provider.ProviderEvent;
import org.keycloak.provider.ProviderEventListener;

/**
 *
 * @author hmlnarik
 */
public class MapClientProviderFactory extends AbstractMapProviderFactory<ClientProvider> implements ClientProviderFactory, ProviderEventListener {

    private final ConcurrentHashMap<UUID, ConcurrentMap<String, Integer>> REGISTERED_NODES_STORE = new ConcurrentHashMap<>();

    private MapStorage<UUID, MapClientEntity, ClientModel> store;

    private Runnable onClose;

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        MapStorageProvider sp = (MapStorageProvider) factory.getProviderFactory(MapStorageProvider.class);
        this.store = sp.getStorage("clients", UUID.class, MapClientEntity.class, ClientModel.class);

        factory.register(this);
        onClose = () -> factory.unregister(this);
    }


    @Override
    public MapClientProvider create(KeycloakSession session) {
        return new MapClientProvider(session, store, REGISTERED_NODES_STORE);
    }

    @Override
    public void close() {
        super.close();
        onClose.run();
    }

    @Override
    public void onEvent(ProviderEvent event) {
        if (event instanceof RoleContainerModel.RoleRemovedEvent) {
            RoleRemovedEvent e = (RoleContainerModel.RoleRemovedEvent) event;
            RoleModel role = e.getRole();
            RoleContainerModel container = role.getContainer();
            RealmModel realm;
            if (container instanceof RealmModel) {
                realm = (RealmModel) container;
            } else if (container instanceof ClientModel) {
                realm = ((ClientModel) container).getRealm();
            } else {
                return;
            }
            create(e.getKeycloakSession()).preRemove(realm, role);
        }
    }
}
