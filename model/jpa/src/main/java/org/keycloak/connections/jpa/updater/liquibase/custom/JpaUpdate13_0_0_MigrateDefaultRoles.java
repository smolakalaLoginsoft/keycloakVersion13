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
package org.keycloak.connections.jpa.updater.liquibase.custom;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import liquibase.exception.CustomChangeException;
import liquibase.statement.core.InsertStatement;
import liquibase.statement.core.RawSqlStatement;
import liquibase.statement.core.UpdateStatement;
import liquibase.structure.core.Table;
import org.keycloak.models.Constants;

public class JpaUpdate13_0_0_MigrateDefaultRoles extends CustomKeycloakTask {

    private final Set<String> realmIds = new HashSet<>();

    @Override
    protected void generateStatementsImpl() throws CustomChangeException {

        extractRealmIds("SELECT ID FROM " + getTableName("REALM"));

        String clientTable = getTableName("CLIENT");
        String clientDefaultRolesTable = getTableName("CLIENT_DEFAULT_ROLES");
        String compositeRoleTable = getTableName("COMPOSITE_ROLE");

        for (String realmId : realmIds) {
            String id = UUID.randomUUID().toString();
            String roleName = determineDefaultRoleName(realmId);
            statements.add(
                // create new default role
                new InsertStatement(null, null, database.correctObjectName("KEYCLOAK_ROLE", Table.class))
                    .addColumnValue("ID", id)
                    .addColumnValue("CLIENT_REALM_CONSTRAINT", realmId)
                    .addColumnValue("CLIENT_ROLE", Boolean.FALSE)
                    .addColumnValue("DESCRIPTION", "${role_" + roleName + "}")
                    .addColumnValue("NAME", roleName)
                    .addColumnValue("REALM_ID", realmId)
                    .addColumnValue("REALM", realmId)
            );
            statements.add(
                // assign the role to the realm
                new UpdateStatement(null, null, database.correctObjectName("REALM", Table.class))
                    .addNewColumnValue("DEFAULT_ROLE", id)
                    .setWhereClause("REALM.ID = '" + realmId + "'")
            );

            statements.add(
                // copy data from REALM_DEFAULT_ROLES to COMPOSITE_ROLE
                new RawSqlStatement("INSERT INTO " + compositeRoleTable + " (COMPOSITE, CHILD_ROLE) " +
                        "SELECT '" + id + "', ROLE_ID FROM " + getTableName("REALM_DEFAULT_ROLES") +
                        " WHERE REALM_ID = '" + realmId + "'")
            );
            statements.add(
                // copy data from CLIENT_DEFAULT_ROLES to COMPOSITE_ROLE
                new RawSqlStatement("INSERT INTO " + compositeRoleTable + " (COMPOSITE, CHILD_ROLE) " +
                        "SELECT '" + id + "', " + clientDefaultRolesTable + ".ROLE_ID FROM " + 
                        clientDefaultRolesTable + " INNER JOIN " + clientTable + " ON " + 
                        clientTable + ".ID = " + clientDefaultRolesTable + ".CLIENT_ID AND " +
                        clientTable + ".REALM_ID = '" + realmId + "'")
            );
        }
    }

    private void extractRealmIds(String sql) throws CustomChangeException {
        try (PreparedStatement statement = jdbcConnection.prepareStatement(sql);
                ResultSet rs = statement.executeQuery()) {

            while (rs.next()) {
                String realmId = rs.getString(1);

                if (realmId == null || realmId.trim().isEmpty()) {
                    continue;
                }

                realmIds.add(realmId);
            }

        } catch (Exception e) {
            throw new CustomChangeException(getTaskId() + ": Exception when extracting data from previous version", e);
        }
    }

    private String determineDefaultRoleName(String realmId) throws CustomChangeException {
        String roleName = Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + realmId.toLowerCase();
        if (isRoleNameAvailable(realmId, roleName)) {
            return roleName;
        } else {
            for (int i = 1; i < Integer.MAX_VALUE; i++) {
                roleName = Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + realmId.toLowerCase() + "-" + i;
                if (isRoleNameAvailable(realmId, roleName)) return roleName;
            }
        }
        throw new CustomChangeException(getTaskId() + ": Exception when extracting data from previous version. Unable to determine default role name.");
    }

    private boolean isRoleNameAvailable(String realmId, String roleName) throws CustomChangeException {
        try (PreparedStatement statement = jdbcConnection.prepareStatement("SELECT ID FROM " + getTableName("KEYCLOAK_ROLE") + 
                " WHERE REALM_ID=? AND NAME=?")) {
            statement.setString(1, realmId);
            statement.setString(2, roleName);
            try (ResultSet rs = statement.executeQuery()) {
                return ! rs.next(); //name is available
            }
        } catch (Exception e) {
            throw new CustomChangeException(getTaskId() + ": Exception when extracting data from previous version", e);
        }
    }

    @Override
    protected String getTaskId() {
        return "Migrate Default roles (13.0.0)";
    }

}
