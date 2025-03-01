package no.fintlabs.opa.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.List;

@Getter
@Setter
@EqualsAndHashCode
@ToString
public class MenuItemsResponse {

    @JsonProperty("result")
    private List<MenuItem> menuItems;
}
