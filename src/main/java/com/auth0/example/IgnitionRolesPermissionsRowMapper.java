package com.auth0.example;


import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

public class IgnitionRolesPermissionsRowMapper implements RowMapper<IgnitionRolesPermissions> {

    @Override
    public IgnitionRolesPermissions mapRow(ResultSet rs, int rowNum) throws SQLException {
        IgnitionRolesPermissions roles_permissions = new IgnitionRolesPermissions();

        roles_permissions.setRoles(rs.getString("roles"));
        roles_permissions.setPermissions(rs.getString("permissions"));

        return roles_permissions;
    }
}
