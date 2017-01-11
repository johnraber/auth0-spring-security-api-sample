package com.auth0.example;

import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;


public class IgnitionUserRowMapper implements RowMapper<IgnitionUser> {

    @Override
    public IgnitionUser mapRow(ResultSet rs, int rowNum) throws SQLException {
        IgnitionUser ignition_user = new IgnitionUser();

        ignition_user.setId(rs.getLong("id"));
        ignition_user.setEmail(rs.getString("email"));
        ignition_user.setOrgId(rs.getLong("org_id"));
        ignition_user.setAuth0Id(rs.getString("auth0_id"));
        ignition_user.setCreatedAt(rs.getString("created_at"));
        ignition_user.setModifiedAt(rs.getString("updated_at"));

        return ignition_user;
    }
}
