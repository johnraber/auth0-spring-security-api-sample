package com.auth0.example;

import java.util.Collection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import java.io.IOException;

import java.security.Principal;
import org.springframework.security.core.Authentication;
//import org.springframework.stereotype.Repository;
// import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.beans.factory.annotation.Autowired;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import com.auth0.spring.security.api.Auth0JWTToken;
import com.auth0.spring.security.api.Auth0UserDetails;


public class IgnitionAuthorizationFilter extends OncePerRequestFilter {

    @Autowired
    JdbcTemplate jdbcTemplate;

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());


    private final String insert_auth0_user_query = "INSERT INTO idl_user.auth0_user(auth0_id, emails) VALUES ($auth0_id, $emails);";
    private final String insert_idl_user_query = "INSERT INTO idl_user.user(auth0_id) VALUES ($auth0_id);";
    private final String insert_app_user_query = "INSERT INTO idl_user.app_user(user_id, app_id, roles, permissions) VALUES ($user_id, $app_id, $roles, $permissions);";
   // private final String auth0_user_exist_query = "SELECT auth0_id FROM idl_user.auth0_user WHERE auth0_id = $id LIMIT 1;";
   private final String auth0_user_exist_query = "SELECT auth0_id FROM idl_user.auth0_user WHERE auth0_id = auth0|5848d2b84c07ab1b49a6ac6d LIMIT 1;";
    private final String find_user_query = "SELECT id FROM idl_user.user WHERE auth0_id = $auth0_id LIMIT 1;";
    private final String get_app_user_roles_and_permissions_query = "SELECT roles, permissions FROM idl_user.app_user au, idl_user.user u WHERE u.auth0_id = $auth0_id and au.user_id = u.id and au.app_id = $app_id;";


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        logger.info("************************** doFilterInternal");


//        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // Auth0JWTToken) authentication
//        final Auth0UserDetails principal = (Auth0UserDetails) authentication.getPrincipal();
//        Principal principal = request.getUserPrincipal();

        Auth0JWTToken auth0_jwt_token = (Auth0JWTToken) request.getUserPrincipal();
        logger.info("*********** auth0JWTToken: ", auth0_jwt_token.toString() );

        Auth0UserDetails auth0_user_details = (Auth0UserDetails) auth0_jwt_token.getPrincipal();
        logger.info("*********** auth0UserDetails: ", auth0_user_details.toString() );

//        SecurityContextHolder.getContext().setAuthentication(
//                new Auth0JWTToken(auth0JWTToken) );

        GrantedAuthority application_based_authority = new SimpleGrantedAuthority("ROLE_ADMIN");
        Collection granted_auths = auth0_user_details.getAuthorities();
        granted_auths.add(application_based_authority);

//        auth0_user_details.getAuthorities().add( application_based_autority );
//        Auth0UserDetails enhanced_auth0_user_details = new Auth0UserDetails(auth0_user_details.);
//        auth0_jwt_token.setPrincipal(enhanced_auth0_user_details);

  //  user_id , name,  email,  email_verified true
        //    Collection<GrantedAuthority> authorities = auth0JWTToken.getAuthorities()  OR
        //    Collection<GrantedAuthority> authorities = auth0UserDetails.getAuthorities()  OR

//        auth0JWTToken.addGrantedAuthorities("ADMIN");

        /**
         Collection<SimpleGrantedAuthority> oldAuthorities = (Collection<SimpleGrantedAuthority>)SecurityContextHolder.getContext().getAuthentication().getAuthorities();
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_ANOTHER");
        List<SimpleGrantedAuthority> updatedAuthorities = new ArrayList<SimpleGrantedAuthority>();
        updatedAuthorities.add(authority);
        updatedAuthorities.addAll(oldAuthorities);

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        SecurityContextHolder.getContext().getAuthentication().getPrincipal(),
                        SecurityContextHolder.getContext().getAuthentication().getCredentials(),
                        updatedAuthorities)
        );
         */

        try {

//            Object[] args = new Object[]{"some_auth0_id"};

//            String existing_user_auth0_id = jdbcTemplate.queryForObject(auth0_user_exist_query, null, String.class);
//            logger.info("********************* found existing user: ", existing_user_auth0_id);
            filterChain.doFilter(request, response);
        }
        catch (Exception ex) {
            logger.error("got error accessing db: ", ex);
            throw ex;
        }
    }


    // accessToken is the token to call Auth0 API (not needed in the most cases)
    // extraParams.id_token has the JSON Web Token
    // profile has all the information from the user


    // NOTE:  this callback only gets called when the user has to authenticate.  Once they have authenticated, this
    //  callback does not execute until the user token expires, the user logs out, the server (or entire cluster),
    //  is rebooted or you require the user to relogin when visiting this app ( Auth0 lock rememberLastLogin: false).

//        return db.transaction({isolationLevel: Sequelize.Transaction.ISOLATION_LEVELS.READ_COMMITTED}, function (txn) {
//
//            return db.query(auth0_user_exist_query, {
//                    bind: { id: profile.id },
//            type: Sequelize.QueryTypes.SELECT,
//                    transaction: txn
//    }).then(function (result) {
//
//                // if user does not exist, create the user
//                if(result.length === 0) {
//
//                    var user_emails = [];
//                    if(profile.emails && profile.emails.length > 0) {
//                        profile.emails.forEach(function(email) {
//                            user_emails.push(email.value);
//                        });
//                    }
//                    return db.query(insert_auth0_user_query, {
//                            bind: { auth0_id: profile.id, emails: JSON.stringify(user_emails) },
//                    type: Sequelize.QueryTypes.INSERT,
//                            transaction: txn
//        }).then(function () {
//                        return db.query(insert_idl_user_query, {
//                                bind: { auth0_id: profile.id },
//                        type: Sequelize.QueryTypes.INSERT,
//                                transaction: txn
//          }).then(function () {
//
//                            return db.query(find_user_query, {
//                                    bind: { auth0_id: profile.id },
//                            type: Sequelize.QueryTypes.SELECT,
//                                    transaction: txn
//            }).then(function (new_user) {
//
//                                // TODO plugin logic to determine roles and permissions
//                                var app_roles = ['admin'];
//                                var app_permissions = ['view_portal_analytics'];
//
//                                return db.query(insert_app_user_query, {
//                                        bind: {
//                                    user_id: new_user[0].id,
//                                            app_id: process.env.AUTH0_CLIENT_ID,
//                                            roles: JSON.stringify(app_roles),
//                                            permissions: JSON.stringify(app_permissions)
//                                },
//                                type: Sequelize.QueryTypes.INSERT,
//                                        transaction: txn
//              }).then(function () {
//
//                                    // ADD new user roles and permissions to the user object created by passport
//                                    return done(null, {profile: profile, extraParams: extraParams, app_roles: app_roles,
//                                            app_permissions: app_permissions});
//                                });
//                            });
//                        });
//                    });
//                }
//                else
//                {
//                    // Regular Login / Not Signup
//                    // TODO possible update user auth0 profile attributes (like emails) in auth0 DB table since these are managed by auth0 (separate system)
//
//                    // do NOT check session cookie for existing roles and permissions, make a database call
//                    //  to possible get updated values ( nominal case since user roles and permissions are managed by IDL not Auth0 )
//
//                    // GET user roles and permissions and ADD to the user object
//                    return db.query(get_app_user_roles_and_permissions_query, {
//                            bind: { auth0_id: profile.id, app_id: process.env.AUTH0_CLIENT_ID},
//                    type: Sequelize.QueryTypes.SELECT,
//                            transaction: txn
//        }).then(function (app_user_roles_permissions) {
//                    return done(null, {profile: profile, extraParams: extraParams, app_roles: app_user_roles_permissions[0].roles,
//                            app_permissions: app_user_roles_permissions[0].permissions});
//                });
//                }
//            });
//        });

}
