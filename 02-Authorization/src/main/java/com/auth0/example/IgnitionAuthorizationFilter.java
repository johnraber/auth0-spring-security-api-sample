package com.auth0.example;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import java.io.IOException;


//import org.springframework.stereotype.Repository;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.beans.factory.annotation.Autowired;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.spring.security.api.Auth0UserDetails;

import com.auth0.SessionUtils;
//import com.auth0.NonceUtils;

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
//        Authentication auth = new UsernamePasswordAuthenticationToken("sub", "password", ImmutableList.of(new SimpleGrantedAuthority("ROLE_API")));
//        SecurityContextHolder.getContext().setAuthentication(auth);
        logger.info("************************** doFilterInternal");

//        final Auth0User user = SessionUtils.getAuth0User(request);

//        NonceUtils.addNonceToStorage(req);
//        final String clientId = getServletContext().getInitParameter("auth0.client_id");
//        final String clientDomain = getServletContext().getInitParameter("auth0.domain");

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
