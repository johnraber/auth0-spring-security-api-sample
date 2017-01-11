package com.auth0.example;

import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;


public class AuthZeroUserRowMapper implements RowMapper<AuthZeroUser> {

    @Override
    public AuthZeroUser mapRow(ResultSet rs, int rowNum) throws SQLException {
        AuthZeroUser auth_zero_user = new AuthZeroUser();

        auth_zero_user.setId(rs.getString("auth0_id"));
        auth_zero_user.setEmail(rs.getString("email"));
        auth_zero_user.setFirstName(rs.getString("first_name"));
        auth_zero_user.setLastName(rs.getString("last_name"));
        auth_zero_user.setCreatedAt(rs.getString("created_at"));
        auth_zero_user.setModifiedAt(rs.getString("updated_at"));

        return auth_zero_user;
    }
}
