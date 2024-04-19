package com.react.demo.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

@Getter
@Setter
public class UserFormDto {

    //@NonNull -> null check
    //@NotEmpty -> null check + "" (빈문자열) check
    //@NotBlank -> null check + "" check + " "(space) check

    @NotBlank
    private String id;

    @NotBlank
    private String name;

    @NotBlank
    private String password;

}
