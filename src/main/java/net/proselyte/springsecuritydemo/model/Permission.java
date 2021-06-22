package net.proselyte.springsecuritydemo.model;

// присваивается к role, которые дают каждой роли определенные права(для чтения к определенному ресурсу,
// для записи к определенному ресурсу, для редактирования и т.п.)
// даёт более гибкий кантроль над секъюрностью нашего приложения
public enum Permission {
    DEVELOPERS_READ("developers:read"),
    DEVELOPERS_WRITE("developers:write");

    private final String permission;

    Permission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
