## Authorization in Spring Security

Authorization in Spring Security is the process where the system determines whether an authenticated client has permission to access a specific resource or perform an action.

### Key Concepts

- **Authorization Filter**: Spring Security uses the `FilterSecurityInterceptor` to enforce authorization rules. It checks if the authenticated user has the required permissions for a requested resource.
- **GrantedAuthority**: Each `UserDetails` object can have one or more `GrantedAuthority` instances, representing permissions or roles (e.g., "read", "write", or "ROLE_ADMIN").
- **Authority-Based Authorization**:
  - Use `hasAuthority(String authority)` to check for a specific permission.
  - Use `hasAnyAuthority(String... authorities)` to allow access if the user has any of the specified permissions.
  - Use `access(String spelExpression)` for complex authorization logic using Spring Expression Language (SpEL). Avoid overuse to prevent complexity.
- **Role-Based Authorization**:
  - Roles are authorities prefixed with "ROLE_" (e.g., "ROLE_ADMIN", "ROLE_USER").
  - Use `hasRole(String role)` to check for a specific role (no need to include "ROLE_" prefix).
  - Use `hasAnyRole(String... roles)` for multiple roles.
  - When using the `roles()` method in `User` builder, Spring automatically adds the "ROLE_" prefix to the role name.

### Code Example

Below is the provided code, organized and commented for clarity, demonstrating authorization with Spring Security.

```java
package com.rajan.springbootrecipies;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class SpringbootrecipiesApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringbootrecipiesApplication.class, args);
    }
}

@Configuration
class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Enable HTTP Basic authentication
            .httpBasic(Customizer.withDefaults())
            // Configure authorization rules
            .authorizeHttpRequests(req -> req
                // Require "write" authority for /write/**
                .requestMatchers("/write/**").hasAuthority("write")
                // Allow "read" or "write" authority for /read/**
                .requestMatchers("/read/**").hasAnyAuthority("write", "read")
                // Require "ROLE_magic" role for /magic/**
                .requestMatchers("/magic/**").hasRole("magic")
                // All other requests require authentication
                .anyRequest().authenticated()
            );
        return http.build();
    }

    @Bean
    UserDetailsService userDetailsService() {
        // Define users with authorities and roles
        var admin = User.withUsername("root")
            .password("root")
            .authorities("read", "write")
            .build();
        var user = User.withUsername("user")
            .password("user")
            .authorities("read")
            .build();
        // Using roles() automatically adds "ROLE_" prefix
        var magicUser = User.withUsername("magic")
            .password("magic")
            .roles("magic") // Becomes "ROLE_magic"
            .build();
        return new InMemoryUserDetailsManager(admin, user, magicUser);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance(); // Note: Use BCryptPasswordEncoder in production
    }
}

@RestController
class GreetController {

    @GetMapping("/read")
    public String greet() {
        return "hello world";
    }

    @GetMapping("/write")
    public String publicPage() {
        return "this is admin page";
    }

    @GetMapping("/magic")
    public String magic() {
        return "this is magic page only accessible by magic user";
    }
}
```
