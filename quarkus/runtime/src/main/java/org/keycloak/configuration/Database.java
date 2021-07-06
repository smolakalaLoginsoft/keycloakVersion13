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

package org.keycloak.configuration;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

class Database {

    private static Map<String, Vendor> DATABASES = new HashMap<>();

    static {
        for (Vendor vendor : Vendor.values()) {
            DATABASES.put(vendor.name().toLowerCase(), vendor);

            for (String alias : vendor.aliases) {
                DATABASES.put(alias, vendor);
            }
        }
    }

    static boolean isSupported(String alias) {
        return DATABASES.containsKey(alias);
    }

    static Optional<String> getDefaultUrl(String alias) {
        Vendor vendor = DATABASES.get(alias);

        if (vendor == null) {
            return Optional.empty();
        }

        return Optional.of(vendor.defaultUrl.apply(alias));
    }

    static Optional<String> getDriver(String alias) {
        Vendor vendor = DATABASES.get(alias);

        if (vendor == null) {
            return Optional.empty();
        }

        return Optional.of(vendor.driver);
    }
    
    static Optional<String> getDialect(String alias) {
        Vendor vendor = DATABASES.get(alias);
        
        if (vendor == null) {
            return Optional.empty();
        }
        
        return Optional.of(vendor.dialect.apply(alias));
    }

    private enum Vendor {
        H2("org.h2.jdbcx.JdbcDataSource", "io.quarkus.hibernate.orm.runtime.dialect.QuarkusH2Dialect",
                new Function<String, String>() {
                    @Override
                    public String apply(String alias) {
                        if ("h2-file".equalsIgnoreCase(alias)) {
                            return "jdbc:h2:file:${kc.home.dir:${kc.db.url.path:~}}" + File.separator + "${kc.data.dir:data}" + File.separator + "keycloakdb${kc.db.url.properties:;;AUTO_SERVER=TRUE}";
                        }
                        return "jdbc:h2:mem:keycloakdb${kc.db.url.properties:}";
                    }
                }, "h2-mem", "h2-file"),
        MYSQL("com.mysql.cj.jdbc.MysqlXADataSource", "org.hibernate.dialect.MySQL8Dialect",
                "jdbc:mysql://${kc.db.url.host:localhost}/${kc.db.url.database:keycloak}${kc.db.url.properties:}"),
        MARIADB("org.mariadb.jdbc.MySQLDataSource", "org.hibernate.dialect.MariaDBDialect",
                "jdbc:mariadb://${kc.db.url.host:localhost}/${kc.db.url.database:keycloak}${kc.db.url.properties:}"),
        POSTGRES("org.postgresql.xa.PGXADataSource", new Function<String, String>() {
            @Override
            public String apply(String alias) {
                if ("postgres-95".equalsIgnoreCase(alias)) {
                    return "io.quarkus.hibernate.orm.runtime.dialect.QuarkusPostgreSQL95Dialect";
                }
                return "io.quarkus.hibernate.orm.runtime.dialect.QuarkusPostgreSQL10Dialect";
            }
        }, "jdbc:postgresql://${kc.db.url.host:localhost}/${kc.db.url.database:keycloak}${kc.db.url.properties:}",
                "postgres-95", "postgres-10");

        final String driver;
        final Function<String, String> dialect;
        final Function<String, String> defaultUrl;
        final String[] aliases;

        Vendor(String driver, String dialect, String defaultUrl, String... aliases) {
            this(driver, (alias) -> dialect, (alias) -> defaultUrl, aliases);
        }

        Vendor(String driver, String dialect, Function<String, String> defaultUrl, String... aliases) {
            this(driver, (alias) -> dialect, defaultUrl, aliases);
        }

        Vendor(String driver, Function<String, String> dialect, String defaultUrl, String... aliases) {
            this(driver, dialect, (alias) -> defaultUrl, aliases);
        }

        Vendor(String driver, Function<String, String> dialect, Function<String, String> defaultUrl, String... aliases) {
            this.driver = driver;
            this.dialect = dialect;
            this.defaultUrl = defaultUrl;
            this.aliases = aliases;
        }
    }
}
