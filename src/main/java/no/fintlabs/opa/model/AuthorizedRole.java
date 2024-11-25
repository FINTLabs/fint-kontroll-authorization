package no.fintlabs.opa.model;

import lombok.Getter;

import java.util.List;
import java.util.Optional;

@Getter
public enum AuthorizedRole {
    PORTAL_ADMIN("Portaladmin", "pa"),
    SYSTEM_ADMIN("Systemadministrator", "sa"),
    RESSURS_ADMIN("Ressursadministrator", "ra"),
    TJENESTE_ADMIN("Tjenesteadministrator", "ta"),
    TILDELER("Tildeler", "td"),
    GODKJENNER("Godkjenner", "g"),
    LEDER("Leder", "l"),
    SLUTTBRUKER("Sluttbruker", "sb");

    private final String name;
    private final String shortName;

    AuthorizedRole(String name, String shortName) {
        this.name = name;
        this.shortName = shortName;
    }

    public static Optional<AuthorizedRole> getRoleByShortName(String shortName) {
        for (AuthorizedRole authorizedRole : AuthorizedRole.values()) {
            if (authorizedRole.shortName.equals(shortName)) {
                return Optional.of(authorizedRole);
            }
        }
        return Optional.empty();
    }

    public static List<String> getValidAssignmentRolesForRessursAdmin() {
        return List.of(TJENESTE_ADMIN.shortName, TILDELER.shortName, GODKJENNER.shortName, LEDER.shortName, SLUTTBRUKER.shortName);
    }

    public static List<String> getValidAssignmentRolesForTjenesteAdmin() {
        return List.of(TILDELER.shortName, GODKJENNER.shortName, LEDER.shortName, SLUTTBRUKER.shortName);
    }

}
