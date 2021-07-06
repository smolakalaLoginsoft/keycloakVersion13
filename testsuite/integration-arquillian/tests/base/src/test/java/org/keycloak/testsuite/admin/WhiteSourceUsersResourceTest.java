package org.keycloak.testsuite.admin;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.Test;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.util.AdminEventPaths;

import javax.ws.rs.core.Response;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class WhiteSourceUsersResourceTest extends AbstractAdminTest {

    @Deployment
    public static JavaArchive createDeployment() {
        return ShrinkWrap.create(JavaArchive.class)
                .addAsManifestResource(EmptyAsset.INSTANCE, "beans.xml");
    }

    private String createUser(UserRepresentation userRep) {
        return createUser(userRep, true);
    }

    private String createUser(UserRepresentation userRep, boolean assertAdminEvent) {
        Response response = realm.users().create(userRep);
        String createdId = ApiUtil.getCreatedId(response);
        response.close();

        if (assertAdminEvent) {
            assertAdminEvents.assertEvent(realmId, OperationType.CREATE, AdminEventPaths.userResourcePath(createdId), userRep,
                    ResourceType.USER);
        }

        getCleanup().addUserId(createdId);

        return createdId;
    }

    @Test
    public void GetUserTest() {
        System.out.println("--**-- WhiteSourceUsersResourceTest start --**--");

        UserRepresentation user1 = new UserRepresentation();
        user1.setUsername("user1");
        String user1Id = createUser(user1);

        UserRepresentation user2 = realm.users().get(user1Id).toRepresentation();

        assertEquals(user1Id, user2.getId());

        UserRepresentation user3 = null;
        try {
            user3 = realm.users().get("SQLi").toRepresentation();
        } catch (Exception e) {
            System.out.println("Error Message: " + e.getMessage());
        }

        assertNull(user3);

        System.out.println("--**-- WhiteSourceUsersResourceTest end --**--");
    }
}
