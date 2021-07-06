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

package org.keycloak.testsuite.admin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import org.hamcrest.CoreMatchers;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.admin.client.resource.RealmLocalizationResource;

import java.util.List;
import java.util.Map;

import javax.ws.rs.NotFoundException;


public class RealmRealmLocalizationResourceTest extends AbstractAdminTest {

    private RealmLocalizationResource resource;

    @Before
    public void before() {
        adminClient.realm(REALM_NAME).localization().saveRealmLocalizationText("en", "key-a", "text-a_en");
        adminClient.realm(REALM_NAME).localization().saveRealmLocalizationText("en", "key-b", "text-b_en");
        adminClient.realm(REALM_NAME).localization().saveRealmLocalizationText("de", "key-a", "text-a_de");

        getCleanup().addLocalization("en");
        getCleanup().addLocalization("de");

        resource = adminClient.realm(REALM_NAME).localization();
    }

    @Test
    public void getRealmSpecificLocales() {
        List<String> languages = resource.getRealmSpecificLocales();
        assertEquals(2, languages.size());
        assertThat(languages, CoreMatchers.hasItems("en", "de"));
    }

    @Test
    public void getRealmLocalizationTexts() {
        Map<String, String> localizations = resource.getRealmLocalizationTexts("en");
        assertNotNull(localizations);
        assertEquals(2, localizations.size());

        assertEquals("text-a_en", localizations.get("key-a"));
        assertEquals("text-b_en", localizations.get("key-b"));
    }

    @Test
    public void getRealmLocalizationsNotExists() {
        Map<String, String> localizations = resource.getRealmLocalizationTexts("zz");
        assertNotNull(localizations);
        assertEquals(0, localizations.size());
    }

    @Test
    public void getRealmLocalizationText() {
        String localizationText = resource.getRealmLocalizationText("en", "key-a");
        assertNotNull(localizationText);
        assertEquals("text-a_en", localizationText);
    }

    @Test(expected = NotFoundException.class)
    public void getRealmLocalizationTextNotExists() {
        resource.getRealmLocalizationText("en", "key-zz");
    }

    @Test
    public void addRealmLocalizationText() {
        resource.saveRealmLocalizationText("en", "key-c", "text-c");

        String localizationText = resource.getRealmLocalizationText("en", "key-c");

        assertNotNull(localizationText);
        assertEquals("text-c", localizationText);
    }

    @Test
    public void updateRealmLocalizationText() {
        resource.saveRealmLocalizationText("en", "key-b", "text-b-new");

        String localizationText = resource.getRealmLocalizationText("en", "key-b");

        assertNotNull(localizationText);
        assertEquals("text-b-new", localizationText);
    }

    @Test
    public void deleteRealmLocalizationText() {
        resource.deleteRealmLocalizationText("en", "key-a");

        Map<String, String> localizations = resource.getRealmLocalizationTexts("en");
        assertEquals(1, localizations.size());
        assertEquals("text-b_en", localizations.get("key-b"));
    }

    @Test(expected = NotFoundException.class)
    public void deleteRealmLocalizationTextNotExists() {
        resource.deleteRealmLocalizationText("en", "zz");
    }

    @Test
    public void deleteRealmLocalizationTexts() {
        resource.deleteRealmLocalizationTexts("en");

        List<String> localizations = resource.getRealmSpecificLocales();
        assertEquals(1, localizations.size());

        assertThat(localizations, CoreMatchers.hasItems("de"));
    }
}
