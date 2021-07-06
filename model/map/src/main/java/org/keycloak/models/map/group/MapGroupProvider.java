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

package org.keycloak.models.map.group;

import org.jboss.logging.Logger;
import org.keycloak.models.GroupModel;
import org.keycloak.models.GroupModel.SearchableFields;
import org.keycloak.models.GroupProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.map.common.Serialization;
import org.keycloak.models.map.storage.MapKeycloakTransaction;
import org.keycloak.models.map.storage.MapStorage;

import org.keycloak.models.map.storage.ModelCriteriaBuilder;
import org.keycloak.models.map.storage.ModelCriteriaBuilder.Operator;
import java.util.Comparator;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import static org.keycloak.common.util.StackUtil.getShortStackTrace;
import static org.keycloak.utils.StreamsUtil.paginatedStream;

public class MapGroupProvider implements GroupProvider {

    private static final Logger LOG = Logger.getLogger(MapGroupProvider.class);
    private final KeycloakSession session;
    final MapKeycloakTransaction<UUID, MapGroupEntity, GroupModel> tx;
    private final MapStorage<UUID, MapGroupEntity, GroupModel> groupStore;

    public MapGroupProvider(KeycloakSession session, MapStorage<UUID, MapGroupEntity, GroupModel> groupStore) {
        this.session = session;
        this.groupStore = groupStore;
        this.tx = groupStore.createTransaction(session);
        session.getTransactionManager().enlist(tx);
    }

    private MapGroupEntity registerEntityForChanges(MapGroupEntity origEntity) {
        final MapGroupEntity res = Serialization.from(origEntity);
        tx.updateIfChanged(origEntity.getId(), res, MapGroupEntity::isUpdated);
        return res;
    }

    private Function<MapGroupEntity, GroupModel> entityToAdapterFunc(RealmModel realm) {
        // Clone entity before returning back, to avoid giving away a reference to the live object to the caller
        return origEntity -> new MapGroupAdapter(session, realm, registerEntityForChanges(origEntity));
    }

    @Override
    public GroupModel getGroupById(RealmModel realm, String id) {
        if (id == null) {
            return null;
        }

        LOG.tracef("getGroupById(%s, %s)%s", realm, id, getShortStackTrace());


        UUID uid;
        try {
            uid = UUID.fromString(id);
        } catch (IllegalArgumentException ex) {
            return null;
        }
        
        MapGroupEntity entity = tx.read(uid);
        String realmId = realm.getId();
        return (entity == null || ! Objects.equals(realmId, entity.getRealmId()))
                ? null
                : entityToAdapterFunc(realm).apply(entity);
    }

    @Override
    public Stream<GroupModel> getGroupsStream(RealmModel realm) {
        return getGroupsStreamInternal(realm, null);
    }

    private Stream<GroupModel> getGroupsStreamInternal(RealmModel realm, UnaryOperator<ModelCriteriaBuilder<GroupModel>> modifier) {
        LOG.tracef("getGroupsStream(%s)%s", realm, getShortStackTrace());
        ModelCriteriaBuilder<GroupModel> mcb = groupStore.createCriteriaBuilder()
          .compare(SearchableFields.REALM_ID, Operator.EQ, realm.getId());

        if (modifier != null) {
            mcb = modifier.apply(mcb);
        }

        return tx.getUpdatedNotRemoved(mcb)
                .map(entityToAdapterFunc(realm))
                .sorted(GroupModel.COMPARE_BY_NAME)
                ;
    }

    @Override
    public Stream<GroupModel> getGroupsStream(RealmModel realm, Stream<String> ids, String search, Integer first, Integer max) {
        ModelCriteriaBuilder<GroupModel> mcb = groupStore.createCriteriaBuilder()
          .compare(SearchableFields.ID, Operator.IN, ids.map(UUID::fromString))
          .compare(SearchableFields.REALM_ID, Operator.EQ, realm.getId());

        if (search != null) {
            mcb = mcb.compare(SearchableFields.NAME, Operator.ILIKE, "%" + search + "%");
        }

        Stream<GroupModel> groupModelStream = tx.getUpdatedNotRemoved(mcb)
          .map(entityToAdapterFunc(realm))
          .sorted(Comparator.comparing(GroupModel::getName));

        return paginatedStream(groupModelStream, first, max);
    }

    @Override
    public Long getGroupsCount(RealmModel realm, Boolean onlyTopGroups) {
        LOG.tracef("getGroupsCount(%s, %s)%s", realm, onlyTopGroups, getShortStackTrace());
        ModelCriteriaBuilder<GroupModel> mcb = groupStore.createCriteriaBuilder()
          .compare(SearchableFields.REALM_ID, Operator.EQ, realm.getId());

        if (Objects.equals(onlyTopGroups, Boolean.TRUE)) {
            mcb = mcb.compare(SearchableFields.PARENT_ID, Operator.EQ, (Object) null);
        }

        return tx.getCount(mcb);
    }

    @Override
    public Long getGroupsCountByNameContaining(RealmModel realm, String search) {
        ModelCriteriaBuilder<GroupModel> mcb = groupStore.createCriteriaBuilder()
          .compare(SearchableFields.REALM_ID, Operator.EQ, realm.getId())
          .compare(SearchableFields.NAME, Operator.ILIKE, "%" + search + "%");

        return tx.getCount(mcb);
    }

    @Override
    public Stream<GroupModel> getGroupsByRoleStream(RealmModel realm, RoleModel role, Integer firstResult, Integer maxResults) {
        LOG.tracef("getGroupsByRole(%s, %s, %d, %d)%s", realm, role, firstResult, maxResults, getShortStackTrace());
        Stream<GroupModel> groupModelStream = getGroupsStreamInternal(realm,
          (ModelCriteriaBuilder<GroupModel> mcb) -> mcb.compare(SearchableFields.ASSIGNED_ROLE, Operator.EQ, role.getId())
        );

        return paginatedStream(groupModelStream, firstResult, maxResults);
    }

    @Override
    public Stream<GroupModel> getTopLevelGroupsStream(RealmModel realm) {
        LOG.tracef("getTopLevelGroupsStream(%s)%s", realm, getShortStackTrace());
        return getGroupsStreamInternal(realm,
          (ModelCriteriaBuilder<GroupModel> mcb) -> mcb.compare(SearchableFields.PARENT_ID, Operator.EQ, (Object) null)
        );
    }

    @Override
    public Stream<GroupModel> getTopLevelGroupsStream(RealmModel realm, Integer firstResult, Integer maxResults) {
        Stream<GroupModel> groupModelStream = getTopLevelGroupsStream(realm);
        
        return paginatedStream(groupModelStream, firstResult, maxResults);
        
    }

    @Override
    public Stream<GroupModel> searchForGroupByNameStream(RealmModel realm, String search, Integer firstResult, Integer maxResults) {
        LOG.tracef("searchForGroupByNameStream(%s, %s, %d, %d)%s", realm, search, firstResult, maxResults, getShortStackTrace());
        Stream<GroupModel> groupModelStream = getGroupsStreamInternal(realm,
          (ModelCriteriaBuilder<GroupModel> mcb) -> mcb.compare(SearchableFields.NAME, Operator.ILIKE, "%" + search + "%")
        );


        return paginatedStream(groupModelStream, firstResult, maxResults);
    }

    @Override
    public GroupModel createGroup(RealmModel realm, String id, String name, GroupModel toParent) {
        LOG.tracef("createGroup(%s, %s, %s, %s)%s", realm, id, name, toParent, getShortStackTrace());
        final UUID entityId = id == null ? UUID.randomUUID() : UUID.fromString(id);

        // Check Db constraint: uniqueConstraints = { @UniqueConstraint(columnNames = {"REALM_ID", "PARENT_GROUP", "NAME"})}
        String parentId = toParent == null ? null : toParent.getId();
        ModelCriteriaBuilder<GroupModel> mcb = groupStore.createCriteriaBuilder()
          .compare(SearchableFields.REALM_ID, Operator.EQ, realm.getId())
          .compare(SearchableFields.PARENT_ID, Operator.EQ, parentId)
          .compare(SearchableFields.NAME, Operator.EQ, name);

        if (tx.getCount(mcb) > 0) {
            throw new ModelDuplicateException("Group with name '" + name + "' in realm " + realm.getName() + " already exists for requested parent" );
        }

        MapGroupEntity entity = new MapGroupEntity(entityId, realm.getId());
        entity.setName(name);
        entity.setParentId(toParent == null ? null : toParent.getId());
        if (tx.read(entity.getId()) != null) {
            throw new ModelDuplicateException("Group exists: " + entityId);
        }
        tx.create(entity.getId(), entity);

        return entityToAdapterFunc(realm).apply(entity);
    }

    @Override
    public boolean removeGroup(RealmModel realm, GroupModel group) {
        LOG.tracef("removeGroup(%s, %s)%s", realm, group, getShortStackTrace());
        if (group == null) return false;

        // TODO: Sending an event (, user group removal and realm default groups) should be extracted to store layer
        session.getKeycloakSessionFactory().publish(new GroupModel.GroupRemovedEvent() {

            @Override
            public RealmModel getRealm() {
                return realm;
            }

            @Override
            public GroupModel getGroup() {
                return group;
            }

            @Override
            public KeycloakSession getKeycloakSession() {
                return session;
            }
        });

        session.users().preRemove(realm, group);
        realm.removeDefaultGroup(group);

        group.getSubGroupsStream().forEach(subGroup -> session.groups().removeGroup(realm, subGroup));

        // TODO: ^^^^^^^ Up to here

        tx.delete(UUID.fromString(group.getId()));
        
        return true;
    }

    /* TODO: investigate following two methods, it seems they could be moved to model layer */

    @Override
    public void moveGroup(RealmModel realm, GroupModel group, GroupModel toParent) {
        LOG.tracef("moveGroup(%s, %s, %s)%s", realm, group, toParent, getShortStackTrace());

        if (toParent != null && group.getId().equals(toParent.getId())) {
            return;
        }
        
        String parentId = toParent == null ? null : toParent.getId();
        ModelCriteriaBuilder<GroupModel> mcb = groupStore.createCriteriaBuilder()
          .compare(SearchableFields.REALM_ID, Operator.EQ, realm.getId())
          .compare(SearchableFields.PARENT_ID, Operator.EQ, parentId)
          .compare(SearchableFields.NAME, Operator.EQ, group.getName());

        try (Stream<MapGroupEntity> possibleSiblings = tx.getUpdatedNotRemoved(mcb)) {
            if (possibleSiblings.findAny().isPresent()) {
                throw new ModelDuplicateException("Parent already contains subgroup named '" + group.getName() + "'");
            }
        }

        if (group.getParentId() != null) {
            group.getParent().removeChild(group);
        }
        group.setParent(toParent);
        if (toParent != null) toParent.addChild(group);
    }

    @Override
    public void addTopLevelGroup(RealmModel realm, GroupModel subGroup) {
        LOG.tracef("addTopLevelGroup(%s, %s)%s", realm, subGroup, getShortStackTrace());

        ModelCriteriaBuilder<GroupModel> mcb = groupStore.createCriteriaBuilder()
          .compare(SearchableFields.REALM_ID, Operator.EQ, realm.getId())
          .compare(SearchableFields.PARENT_ID, Operator.EQ, (Object) null)
          .compare(SearchableFields.NAME, Operator.EQ, subGroup.getName());

        try (Stream<MapGroupEntity> possibleSiblings = tx.getUpdatedNotRemoved(mcb)) {
            if (possibleSiblings.findAny().isPresent()) {
                throw new ModelDuplicateException("There is already a top level group named '" + subGroup.getName() + "'");
            }
        }

        subGroup.setParent(null);
    }

    public void preRemove(RealmModel realm, RoleModel role) {
        LOG.tracef("preRemove(%s, %s)%s", realm, role, getShortStackTrace());
        ModelCriteriaBuilder<GroupModel> mcb = groupStore.createCriteriaBuilder()
          .compare(SearchableFields.REALM_ID, Operator.EQ, realm.getId())
          .compare(SearchableFields.ASSIGNED_ROLE, Operator.EQ, role.getId());
        try (Stream<MapGroupEntity> toRemove = tx.getUpdatedNotRemoved(mcb)) {
            toRemove
                .map(groupEntity -> session.groups().getGroupById(realm, groupEntity.getId().toString()))
                .forEach(groupModel -> groupModel.deleteRoleMapping(role));
        }
    }

    @Override
    public void close() {
        
    }

}
