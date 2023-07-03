package com.codewithaditya.blog.payloads;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class CategoryDto {

    private Integer categoryId;

    @NotBlank(message = "tile can not be left empty !!")
    @Size(min = 4, message = "Min size of Category title is 4")
    private String categoryTitle;

    @NotBlank(message = "description can not be left empty !!")
    @Size(min = 10, message = "Min size of Category description is 10")
    private String categoryDescription;
}
