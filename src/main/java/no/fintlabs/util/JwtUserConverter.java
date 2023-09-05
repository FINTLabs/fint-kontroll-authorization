package no.fintlabs.util;

public class JwtUserConverter extends JwtConverter {
        public JwtUserConverter() {
            this.addMapping("organizationid", "ORGID_");
            this.addMapping("organizationnumber", "ORGNR_");
            this.addMapping("roles", "ROLE_");
        }
}
