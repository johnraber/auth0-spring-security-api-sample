package com.auth0.example;

import com.auth0.spring.security.api.Auth0UserDetails;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Collection;


@Service
public class IgnitionUserDataService {

    private JdbcTemplate jdbcTemplate;

    private final String insert_auth0_user_query = "INSERT INTO idl_user.auth0_user(auth0_id, emails) VALUES ($auth0_id, $emails);";
    private final String insert_idl_user_query = "INSERT INTO idl_user.user(auth0_id) VALUES ($auth0_id);";
    private final String insert_app_user_query = "INSERT INTO idl_user.app_user(user_id, app_id, roles, permissions) VALUES ($user_id, $app_id, $roles, $permissions);";
    // private final String auth0_user_exist_query = "SELECT auth0_id FROM idl_user.auth0_user WHERE auth0_id = $id LIMIT 1;";
    private final String auth0_user_exist_query = "SELECT auth0_id FROM idl_user.auth0_user WHERE auth0_id = auth0|5848d2b84c07ab1b49a6ac6d LIMIT 1;";
    private final String find_user_query = "SELECT id FROM idl_user.user WHERE auth0_id = $auth0_id LIMIT 1;";
    private final String get_app_user_roles_and_permissions_query = "SELECT roles, permissions FROM idl_user.app_user au, idl_user.user u WHERE u.auth0_id = $auth0_id and au.user_id = u.id and au.app_id = $app_id;";


    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    public IgnitionUserDataService() {

        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.postgresql.Driver");
        dataSource.setUrl("jdbc:postgresql://localhost:5432/idl");
        dataSource.setUsername("postgres");
        dataSource.setPassword("postgres");

        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }


    public void evaluate_user_add_authorities( Auth0UserDetails auth0_user_details) {

        GrantedAuthority application_based_authority = new SimpleGrantedAuthority("ROLE_ADMIN");
        Collection granted_auths = auth0_user_details.getAuthorities();

        granted_auths.add(application_based_authority);


        try {
            Object[] args = new Object[]{"auth0|5848d2b84c07ab1b49a6ac6d"};

            String existing_user_auth0_id = jdbcTemplate.queryForObject(auth0_user_exist_query, null, String.class);
        } catch (Exception ex) {
            logger.error("got error accessing db: ", ex);
            throw ex;
        }
    }
}
