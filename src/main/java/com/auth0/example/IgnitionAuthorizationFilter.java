package com.auth0.example;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import java.io.IOException;

import org.springframework.web.filter.OncePerRequestFilter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.spring.security.api.Auth0JWTToken;
import com.auth0.spring.security.api.Auth0UserDetails;


public class IgnitionAuthorizationFilter extends OncePerRequestFilter {

    IgnitionUserDataService ignitionUserDataService;

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    public IgnitionAuthorizationFilter() {
        this.ignitionUserDataService = new IgnitionUserDataService();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        logger.info("************************** doFilterInternal");

        Auth0JWTToken auth0_jwt_token = (Auth0JWTToken) request.getUserPrincipal();
        Auth0UserDetails auth0_user_details = (Auth0UserDetails) auth0_jwt_token.getPrincipal();

        ignitionUserDataService.evaluate_user_add_authorities(auth0_user_details);

        filterChain.doFilter(request, response);
    }





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
