package no.fintlabs.securityconfig;

import no.fintlabs.opa.OpaAuthorizationManager;
import no.fintlabs.util.JwtUserConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class FintKontrollSecurityConfig {

    @Autowired
    private OpaAuthorizationManager opaAuthorizationManager;

    @Value("${fint.integration.service.authorized-role:${fint.integration.service.authorized-role:rolle}}")
    private String authorizedRole;
    @Value("${fint.integration.service.authorized-org-id:vigo.no}")
    private String authorizedOrgId;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .accessDecisionManager(opaAuthorizationManager)
                .antMatchers("/**")
                .authenticated()
                .and()
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt()
                        .jwtAuthenticationConverter(new JwtUserConverter()));
        return http.build();
    }
}
