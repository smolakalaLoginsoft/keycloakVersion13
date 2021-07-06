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

package org.keycloak.models.jpa.entities;

import java.io.Serializable;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.Table;
import org.keycloak.models.jpa.converter.MapStringConverter;

@Entity
@IdClass(RealmLocalizationTextsEntity.RealmLocalizationTextEntityKey.class)
@Table(name = "REALM_LOCALIZATIONS")
public class RealmLocalizationTextsEntity {

    // TODO: Remove this constant once the quarkus issue is fixed and use the @Convert annotation in the proper JPA way. Ideally see the github history and revert whole commit,
    // which adds this "TODO" once the quarkus issue is fixed
    private static final MapStringConverter MAP_STRING_CONVERTER = new MapStringConverter();

    static public class RealmLocalizationTextEntityKey implements Serializable {
        private String realmId;
        private String locale;

        public String getRealmId() {
            return realmId;
        }

        public void setRealmId(String realmId) {
            this.realmId = realmId;
        }

        public String getLocale() {
            return locale;
        }

        public void setLocale(String locale) {
            this.locale = locale;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            RealmLocalizationTextEntityKey that = (RealmLocalizationTextEntityKey) o;
            return Objects.equals(realmId, that.realmId) &&
                    Objects.equals(locale, that.locale);
        }

        @Override
        public int hashCode() {
            return Objects.hash(realmId, locale);
        }
    }

    @Id
    @Column(name = "REALM_ID")
    private String realmId;

    @Id
    @Column(name = "LOCALE")
    private String locale;

    @Column(name = "TEXTS")
    private String texts;
    // TODO: The @Convert does not work as expected on quarkus. It doesn't update the "texts" in case that updated map has same keys (but different values) as old map had
//    @Convert(converter = MapStringConverter.class)
//    private Map<String,String> texts;

    public Map<String,String> getTexts() {
        if (texts == null) {
            return Collections.emptyMap();
        } else {
            return Collections.unmodifiableMap(MAP_STRING_CONVERTER.convertToEntityAttribute(texts));
        }
    }

    public void setTexts(Map<String,String> texts) {
        if (texts == null) {
            this.texts = null;
        } else {
            this.texts = MAP_STRING_CONVERTER.convertToDatabaseColumn(texts);
        }
    }

    public String getLocale() {
        return locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    @Override
    public String toString() {
        return "LocalizationTextEntity{" +
                ", text='" + texts + '\'' +
                ", locale='" + locale + '\'' +
                ", realmId='" + realmId + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RealmLocalizationTextsEntity that = (RealmLocalizationTextsEntity) o;
        return Objects.equals(realmId, that.realmId) &&
                Objects.equals(locale, that.locale) &&
                Objects.equals(texts, that.texts);
    }

    @Override
    public int hashCode() {
        return Objects.hash(realmId, locale, texts);
    }
}
