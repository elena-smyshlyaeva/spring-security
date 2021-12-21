package com.example.demospringsecurity.domain;

/*
права клиента будут определяться не по его роли, а по его разрешениям (permission).
так достигается бОльшая гибкость.

в данном примере есть разрешение на чтение и запись. запись может делать только админ, а чтение - админ и пользователь.
 */
public enum Permission {
    DEVELOPERS_READ("developers:read"), DEVELOPERS_WRITE("developers:write");
    private final String permission;

    public String getPermission() {
        return permission;
    }

    Permission(String permission) {
        this.permission = permission;
    }
}
