package ru.kuznetsov.shop.auth.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan("ru.kuznetsov.shop.auth.service")
public class KeycloakServiceConfiguration {
}
