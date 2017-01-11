package com.auth0.example;

import com.auth0.spring.security.api.Auth0UserDetails;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.StringReader;
import java.util.Collection;
import com.google.gson.Gson;


@Service
public class IgnitionUserDataService {

    private NamedParameterJdbcTemplate jdbcTemplate;

    private final String insert_auth0_user_query = "INSERT INTO idl_user.auth0_user(auth0_id, email) VALUES ( :auth0_id, :email)";
    private final String insert_idl_user_query = "INSERT INTO idl_user.user(auth0_id) VALUES (:auth0_id)";
    private final String insert_app_user_query = "INSERT INTO idl.service_registry(user_id, service_id, roles, permissions, third_party_client_id) VALUES (:user_id, :service_id, :roles::json, :permissions::json, :third_party_client_id)";
    private final String auth0_user_exist_query = "SELECT * FROM idl_user.auth0_user WHERE auth0_id = :auth0_id";
    private final String find_user_query = "SELECT * FROM idl_user.user WHERE auth0_id = :auth0_id";
    private final String get_app_user_roles_and_permissions_query = "SELECT roles, permissions FROM idl_user.app_user au, idl_user.user u WHERE u.auth0_id = :auth0_id and au.user_id = u.id and au.app_id = ':app_id'";

    private Gson gson = new Gson();

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    public IgnitionUserDataService() {

        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.postgresql.Driver");
        dataSource.setUrl("jdbc:postgresql://localhost:5432/idl");
        dataSource.setUsername("postgres");
        dataSource.setPassword("postgres");

        this.jdbcTemplate = new NamedParameterJdbcTemplate(dataSource);
    }


    public void evaluate_user_add_authorities(Auth0UserDetails auth0_user_details) {

        String auth0_pk = (String) auth0_user_details.getAuth0Attribute("user_id");

        try {
            MapSqlParameterSource namedParameters = new MapSqlParameterSource().addValue("auth0_id", auth0_pk);
            AuthZeroUser existing_user =  jdbcTemplate.queryForObject(auth0_user_exist_query, namedParameters,
                    new AuthZeroUserRowMapper() );


            // Regular Login / Not Signup

            // do NOT assume you can check session cookie for existing roles and permissions, make a database call
            //  to possible get updated values ( nominal case since user roles and permissions are managed by IDL not Auth0 )

            // GET user roles and permissions and ADD to the user object

            // TODO read in the auth0.clientId from auth0.properties file
//            namedParameters.addValue("appId", "bW4hAsU35OkxECU2voRssgZ5GWQIvVhp");
//            IgnitionRolesPermissions user_roles_permissions =  jdbcTemplate.queryForObject(get_app_user_roles_and_permissions_query,
//                    namedParameters, new IgnitionRolesPermissionsRowMapper() );

            // TODO loop thru and add roles
            GrantedAuthority application_based_authority = new SimpleGrantedAuthority("ROLE_ADMIN");
            Collection granted_auths = auth0_user_details.getAuthorities();

            granted_auths.add(application_based_authority);


        } catch (org.springframework.dao.EmptyResultDataAccessException no_existing_user) {

            // if Auth0 user does not exist, create the user in both the Auth0 user table and the Ignition user table

            String email = (String) auth0_user_details.getAuth0Attribute("email");
            MapSqlParameterSource namedParameters = new MapSqlParameterSource().addValue("auth0_id", auth0_pk);
            namedParameters.addValue("email", email);
            int updated_rows = jdbcTemplate.update(insert_auth0_user_query, namedParameters);
            logger.info("inserted a new user from Auth0 into Ignition db idl_user.auth0_user");


            updated_rows = jdbcTemplate.update(insert_idl_user_query, namedParameters);
            logger.info("inserted a new Ignition user into Ignition db idl_user.user");


            namedParameters = new MapSqlParameterSource().addValue("auth0_id", auth0_pk);
            IgnitionUser ignition_user =  jdbcTemplate.queryForObject(find_user_query, namedParameters,
                    new IgnitionUserRowMapper() );

            namedParameters = new MapSqlParameterSource().addValue("user_id", ignition_user.getId() );
            // TODO read in the auth0.clientId from auth0.properties file and find service by service.third_party_auth_app_id ===  auth0.clientId
            //     then use that service.id  for the service_id below
            namedParameters.addValue("service_id", 1);
            namedParameters.addValue("third_party_client_id", "bW4hAsU35OkxECU2voRssgZ5GWQIvVhp");
            namedParameters.addValue("roles",  gson.toJson("[ROLE_ADMIN]")  );
            namedParameters.addValue("permissions", null);
            updated_rows = jdbcTemplate.update(insert_app_user_query, namedParameters);

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
