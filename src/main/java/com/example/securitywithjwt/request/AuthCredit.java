package com.example.securitywithjwt.request;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.Setter;

import java.io.IOException;

@Getter
@Setter
public class AuthCredit {
    private String username;
    private String password;

    @JsonCreator
    public AuthCredit(
            @JsonProperty("username") String username,
            @JsonProperty("password") String password
    ){
        this.username = username;
        this.password = password;
    }

    public static AuthCredit ConvertFromString(String jsonData) throws IOException {
        ObjectMapper om = new ObjectMapper();
        return om.readValue(jsonData, AuthCredit.class);
    }
}