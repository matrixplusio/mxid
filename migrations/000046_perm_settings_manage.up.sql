-- settings.manage gates the console runtime settings endpoints
-- (/api/v1/console/settings/*). These were previously reachable by any
-- authenticated console user (only AuthMiddleware, no authz), letting a
-- low-privilege operator repoint SMTP (-> password-reset interception),
-- weaken MFA/password policy, or downgrade the license. super_admin passes
-- via the casbin "*" wildcard automatically; grant this permission to tenant
-- admin roles through the role UI as needed.
--
-- id uses the governance high-id range (like migration 000045) to avoid any
-- collision with the sequential catalog.
INSERT INTO mxid_permission (id, tenant_id, name, code, resource, action) VALUES
    (904600001, 1, '管理系统设置', 'settings.manage', 'settings', 'manage')
ON CONFLICT (tenant_id, code) DO NOTHING;
