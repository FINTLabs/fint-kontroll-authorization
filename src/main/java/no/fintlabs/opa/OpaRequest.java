package no.fintlabs.opa;

public class OpaRequest {

    private String user;
    private String operation;

    public OpaRequest(String user, String operation) {
        this.user = user;
        this.operation = operation;
    }

    public String getUser() {
        return user;
    }

    public String getOperation() {
        return operation;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }
}
