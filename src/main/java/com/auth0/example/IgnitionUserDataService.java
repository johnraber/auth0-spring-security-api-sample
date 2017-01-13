package com.auth0.example;

import com.auth0.spring.security.api.Auth0UserDetails;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Collection;
import com.google.gson.Gson;


@Configuration
@Service
@PropertySources({
        @PropertySource("classpath:auth0.properties"),
        @PropertySource("classpath:db.properties")
})
public class IgnitionUserDataService {

    private NamedParameterJdbcTemplate jdbcTemplate;
    private ConfigurableEnvironment env;

    private final String insert_auth0_user = "INSERT INTO idl_user.auth0_user(auth0_id, email) VALUES ( :auth0_id, :email)";
    private final String insert_idl_user = "INSERT INTO idl_user.user(auth0_id) VALUES (:auth0_id)";
    private final String insert_app_user = "INSERT INTO idl.service_registry(user_id, service_id, roles, permissions, third_party_client_id) VALUES (:user_id, :service_id, :roles::json, :permissions::json, :third_party_client_id)";
    private final String auth0_user_exist = "SELECT * FROM idl_user.auth0_user WHERE auth0_id = :auth0_id";
    private final String find_user = "SELECT * FROM idl_user.user WHERE auth0_id = :auth0_id";
    private final String get_app_user_roles_and_permissions_query =
            "SELECT roles, permissions FROM idl.service_registry sr, idl_user.user u  WHERE  u.auth0_id = :auth0_id and u.id = sr.user_id and sr.service_id = :service_id";

    private Gson gson = new Gson();

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    public IgnitionUserDataService() {

    }

    private void create_datasource() {

        AnnotationConfigApplicationContext context =
                new AnnotationConfigApplicationContext(IgnitionUserDataService.class);
        env = context.getEnvironment();

        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName(env.getProperty("db.driver.classname") );
        dataSource.setUrl("jdbc:postgresql://" + env.getProperty("db.url") + ":" + env.getProperty("db.port") + "/" +
                env.getProperty("db.name") );
        dataSource.setUsername(env.getProperty("db.username") );
        dataSource.setPassword(env.getProperty("db.password") );

        this.jdbcTemplate = new NamedParameterJdbcTemplate(dataSource);
    }


    public void evaluate_user_add_authorities(Auth0UserDetails auth0_user_details) {

        if(jdbcTemplate == null) {
            create_datasource();
        }

        boolean auth0_verified = (boolean) auth0_user_details.getAuth0Attribute("email_verified");

        if(auth0_verified == false) {
            return;
        }

        String auth0_pk = (String) auth0_user_details.getAuth0Attribute("user_id");

        try {
            MapSqlParameterSource namedParameters = new MapSqlParameterSource().addValue("auth0_id", auth0_pk);
            AuthZeroUser existing_user =  jdbcTemplate.queryForObject(auth0_user_exist, namedParameters,
                    new AuthZeroUserRowMapper() );


            // Regular Login / Not Signup if querying for existing user returns without throwing

            // do NOT assume you can check session cookie for existing roles and permissions, make a database call
            //  to possible get updated values ( nominal case since user roles and permissions are managed by Ignition
            // not Auth0 )

            namedParameters = new MapSqlParameterSource().addValue("auth0_id", existing_user.getId() );
            // TODO this service id should be an application property and MUST correlate to the service id
            //   for this application/service platform in the idl.service table which supports also supports versioning
            namedParameters.addValue("service_id", 1);
            IgnitionRolesPermissions user_app_roles_permissions =  jdbcTemplate.queryForObject(get_app_user_roles_and_permissions_query,
                    namedParameters, new IgnitionRolesPermissionsRowMapper() );

            // TODO loop thru and add roles
            //            user_app_roles_permissions.roles.forEach()
            GrantedAuthority application_based_authority = new SimpleGrantedAuthority("ROLE_ADMIN");
            Collection granted_auths = auth0_user_details.getAuthorities();

            granted_auths.add(application_based_authority);

        } catch (org.springframework.dao.EmptyResultDataAccessException no_existing_user) {

            // if Auth0 user does not exist, create the user in both the Auth0 user table and the Ignition user table
            // note that the Ignition user may exist due to pre-populating the db and sending out an invite
            // to the user

            String email = (String) auth0_user_details.getAuth0Attribute("email");
            MapSqlParameterSource namedParameters = new MapSqlParameterSource().addValue("auth0_id", auth0_pk);
            namedParameters.addValue("email", email);
            int updated_rows = jdbcTemplate.update(insert_auth0_user, namedParameters);
            logger.info("inserted a new user from Auth0 into Ignition db idl_user.auth0_user");


            // TODO check to see if there is an Ignition user with the same email as the incoming new Auth0 user AND
            //   that Ignition user does NOT have existing auth0_id reference.   If so, update the existing Ignition
            //   user's null auth0_id.  This supports putting Ignition users in db and sending out email invites to
            //   correlate them when they signup via Auth0

            updated_rows = jdbcTemplate.update(insert_idl_user, namedParameters);
            logger.info("inserted a new Ignition user into Ignition db idl_user.user");

//            insert user_auth0_user  if after reviewing all the Use Cases the one Ignition user to many Auth0 users is needed
//            namedParameters = new MapSqlParameterSource().addValue("auth0_id", auth0_pk);
//            namedParameters.addValue("user_id", 1);
//            updated_rows = jdbcTemplate.update(insert_idl_user, namedParameters);
//            logger.info("created an association between new Ignition user and new Auth0 user");

            namedParameters = new MapSqlParameterSource().addValue("auth0_id", auth0_pk);
            IgnitionUser ignition_user =  jdbcTemplate.queryForObject(find_user, namedParameters,
                    new IgnitionUserRowMapper() );

            namedParameters = new MapSqlParameterSource().addValue("user_id", ignition_user.getId() );
            // TODO find service by service.third_party_auth_app_id ==  env.getProperty("auth0.clientId")
            //     then use that service.id  for the service_id below
            namedParameters.addValue("service_id", 1);
            namedParameters.addValue("third_party_client_id", env.getProperty("auth0.clientId") );

            // TODO do some cool logic to determine the roles a user should have
            namedParameters.addValue("roles",  gson.toJson("[ROLE_ADMIN]")  );
            namedParameters.addValue("permissions", null);
            updated_rows = jdbcTemplate.update(insert_app_user, namedParameters);

            // TODO loop thru and add roles
            GrantedAuthority application_based_authority = new SimpleGrantedAuthority("ROLE_ADMIN");
            Collection granted_auths = auth0_user_details.getAuthorities();

            granted_auths.add(application_based_authority);

        } catch(Exception ex) {
            logger.error("got error accessing db: ", ex);
            throw ex;
        }
    }
}
