package com.auth0.example;

import com.auth0.spring.security.api.Auth0SecurityConfig;
import com.auth0.spring.security.api.Auth0AuthenticationFilter;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Configuration
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class AppConfig extends Auth0SecurityConfig {

    /**
     * Provides Auth0 API access
     */
    @Bean
    public Auth0Client auth0Client() {
        return new Auth0Client(clientId, issuer);
    }


//    @Bean
//    public DataSource dataSource()
//    {
//        BasicDataSource dataSource = new BasicDataSource();
//        dataSource.setDriverClassName(env.getProperty("jdbc.driverClassName"));
//        dataSource.setUrl(env.getProperty("jdbc.url"));
//        dataSource.setUsername(env.getProperty("jdbc.username"));
//        dataSource.setPassword(env.getProperty("jdbc.password"));
//        return dataSource;
//    }

    /**
     *  Our API Configuration - for Profile CRUD operations
     *
     *  Here we choose not to bother using the `auth0.securedRoute` property configuration
     *  and instead ensure any unlisted endpoint in our config is secured by default
     */
    @Override
    protected void authorizeRequests(final HttpSecurity http) throws Exception {
        // include some Spring Boot Actuator endpoints to check metrics
        // add others or remove as you choose, this is just a sample config to illustrate
        // most specific rules must come - order is important (see Spring Security docs)


//        logger.info("************************** calling authorizeRequests");

//        http.addFilterBefore( new AuthorizationFilter(), Auth0AuthenticationFilter.class);

        http.authorizeRequests()
//                .antMatchers("/ping", "/pong").permitAll()
//                .antMatchers("/api/v1/profiles").permitAll()
//                .antMatchers(HttpMethod.GET, "/api/v1/profiles").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
//                .antMatchers(HttpMethod.GET, "/api/v1/profiles/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
//                .antMatchers(HttpMethod.POST, "/api/v1/profiles/**").hasAnyAuthority("ROLE_ADMIN")
//                .antMatchers(HttpMethod.PUT, "/api/v1/profiles/**").hasAnyAuthority("ROLE_ADMIN")
//                .antMatchers(HttpMethod.DELETE, "/api/v1/profiles/**").hasAnyAuthority("ROLE_ADMIN")
                .anyRequest().authenticated();
    }

    /*
     * Only required for sample purposes..
     */
    String getAuthorityStrategy() {

        return super.authorityStrategy;
    }
}