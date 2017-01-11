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
}
