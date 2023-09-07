package no.fintlabs.opa.model;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class OpaRequest {

    private String user;
    private String operation;
}
