package com.codewithaditya.blog.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI bloggingApplicationOpenAPI() {

        return new OpenAPI()
                .components(new Components()
                        .addSecuritySchemes("bearer-key", new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")))
                .info(new Info().title("Blogging Application : Backend API")
                .description("This project is developed by Aditya Gautam")
                .version("v0.0.1")
                .contact(new Contact().name("Aditya").email("adityaadg1997@gmail.com"))
                .license(new License().name("All Rights Reserve @ 2023").url("http://springdoc.org")))
                .externalDocs(new ExternalDocumentation()
                .description("Spring doc official link")
                .url("http://springdoc.org"));

    }

}
