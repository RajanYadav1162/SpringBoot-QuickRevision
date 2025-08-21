# Spring Boot Method-Level Security Notes

## Overview
Method-level security in Spring Boot allows fine-grained access control at the method level, complementing URL-based security. It is disabled by default and must be explicitly enabled. This document summarizes key concepts, including enabling method security, authorization types, filtering, and their relevance in modern token-based authentication systems like JWT.

## Enabling Method-Level Security
- **Enable with `@EnableMethodSecurity`**: Add this annotation to a `@Configuration` class to enable method-level security. It creates a Spring AOP aspect that intercepts method calls to enforce security rules.
  ```java
  @EnableMethodSecurity
  @Configuration
  class SecurityConfig {
      // Configuration details
  }
  ```
- **How it works**: Without method security, the flow is `Controller -> Service`. With method security enabled, it becomes `Controller -> SecurityAspect -> Service`, where the `SecurityAspect` enforces authorization rules.

## Types of Method Security
Method-level security in Spring Boot can be applied in two primary ways:
1. **Call Authorization**:
   - **Pre-Authorization**: Checks if the caller has permission to invoke the method before execution.
   - **Post-Authorization**: Verifies if the caller is authorized to receive the method's response after execution.
2. **Filtering**:
   - **Pre-Filtering**: Filters input collections or parameters before the method executes.
   - **Post-Filtering**: Filters the method’s return value based on security rules.

## Annotations for Method Security
Spring provides several annotations to enforce method-level security:
1. **@PreAuthorize**:
   - Most commonly used annotation.
   - Uses Spring Expression Language (SpEL) to define access conditions.
   - Example: Restrict access to users with a specific role or authority.
     ```java
     @PreAuthorize("hasRole('write')")
     @GetMapping("/admin/greet")
     public String greetAdmin() {
         return "hello admin user";
     }
     ```
   - Can use SpEL for dynamic checks, e.g., comparing method parameters with the authenticated user:
     ```java
     @PreAuthorize("#name == authentication.principal.username")
     @GetMapping("/friends")
     public List<String> getYourFriendsName(@RequestParam(name="name") String name) {
         // Method logic
     }
     ```
2. **@PostAuthorize**:
   - Checks authorization after the method executes, typically used to filter the response.
   - Example: Allow method execution but restrict the return value based on user permissions.
     ```java
     @PostAuthorize("returnObject.owner == authentication.principal.username")
     public Data getSensitiveData() {
         // Return sensitive data
     }
     ```
3. **@Secured**:
   - Older annotation, less flexible than `@PreAuthorize`.
   - Supports simple role-based checks (e.g., `ROLE_ADMIN`).
   - Example:
     ```java
     @Secured("ROLE_ADMIN")
     public void adminOnlyMethod() {
         // Admin-only logic
     }
     ```
4. **@RolesAllowed**:
   - JSR-250 annotation, similar to `@Secured`.
   - Example:
     ```java
     @RolesAllowed({"ROLE_READ", "ROLE_WRITE"})
     public void restrictedMethod() {
         // Restricted logic
     }
     ```
5. **@PreFilter**:
   - Filters input collections or parameters before the method runs.
   - Example: Filter a list to include only elements the user is authorized to see.
     ```java
     @PreFilter("filterObject.owner == authentication.principal.username")
     public void processList(List<Data> dataList) {
         // Process filtered list
     }
     ```
6. **@PostFilter**:
   - Filters the method’s return value (e.g., a collection) based on security rules.
   - Example: Return only elements the user is authorized to access.
     ```java
     @PostFilter("filterObject.owner == authentication.principal.username")
     public List<Data> getDataList() {
         // Return list of data
     }
     ```

## SpEL (Spring Expression Language) in Method Security
- SpEL is used in `@PreAuthorize`, `@PostAuthorize`, `@PreFilter`, and `@PostFilter` to define complex authorization logic.
- Common expressions:
  - `hasRole('ROLE_NAME')`: Checks if the user has a specific role.
  - `hasAnyRole('ROLE1', 'ROLE2')`: Checks if the user has any of the specified roles.
  - `hasAuthority('PERMISSION')`: Checks for a specific permission.
  - `authentication.principal.username`: Accesses the authenticated user’s username.
  - `#parameterName`: References method parameters.
- Example:
  ```java
  @PreAuthorize("hasRole('read') or #userId == authentication.principal.id")
  public void accessResource(Long userId) {
      // Method logic
  }
  ```

## Example Code
Below is an example of method-level security in a Spring Boot application:
```java
@SpringBootApplication
public class SpringbootrecipiesApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringbootrecipiesApplication.class, args);
    }
}

@EnableMethodSecurity
@Configuration
class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    UserDetailsService userDetailsService() {
        UserDetails publicUser = User.withUsername("user").password("user").roles("read").build();
        UserDetails adminUser = User.withUsername("root").password("root").roles("read", "write").build();
        return new InMemoryUserDetailsManager(publicUser, adminUser);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}

@RestController
class Greet {
    @GetMapping("/public/greet")
    public String greetPublic() {
        return "hello public user";
    }

    @PreAuthorize("hasRole('write')")
    @GetMapping("/admin/greet")
    public String greetAdmin() {
        return "hello admin user";
    }

    @PreAuthorize("#name == authentication.principal.username")
    @GetMapping("/friends")
    public List<String> getYourFriendsName(@RequestParam(name="name") String name) {
        Map<String, List<String>> map = new HashMap<>();
        map.put("user", List.of("a", "b", "c", "d"));
        map.put("admin", List.of("you are admin, no friends"));
        return map.get(name);
    }
}
```

## Method Security in Modern Token-Based Authentication (e.g., JWT)
- **Relevance**: Method-level security is still highly relevant in modern token-based authentication systems like JWT. It complements token-based authorization by providing fine-grained control at the method level.
- **How it works with JWT**:
  - A JWT token typically contains claims (e.g., `roles`, `scopes`, or custom attributes) that define the user’s permissions.
  - Spring Security extracts these claims and maps them to authorities (e.g., `ROLE_USER`, `SCOPE_read`).
  - `@PreAuthorize` and other annotations can reference these authorities or claims using SpEL.
  - Example:
    ```java
    @PreAuthorize("hasAuthority('SCOPE_write')")
    public void modifyResource() {
        // JWT-authorized method
    }
    ```
- **Integration**:
  - Use a `JwtAuthenticationConverter` to map JWT claims to Spring Security authorities.
  - Example:
    ```java
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
        converter.setAuthorityPrefix("SCOPE_");
        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(converter);
        return jwtConverter;
    }
    ```
- **Why it’s useful**:
  - JWT provides coarse-grained access at the endpoint level (e.g., via `HttpSecurity`).
  - Method-level security adds fine-grained control within the application logic, ensuring only authorized users can execute specific methods or access specific data.
  - Example: A user with a valid JWT may access an endpoint, but `@PreAuthorize` can restrict certain method calls based on roles or claims.

## Additional Important Concepts
1. **Global Method Security vs. Web Security**:
   - Method security operates at the service or controller layer, while web security (`HttpSecurity`) controls HTTP requests.
   - Use both for layered security: `HttpSecurity` for coarse-grained URL access, and method security for fine-grained logic control.
2. **Custom Security Expressions**:
   - You can extend SpEL by defining custom security expressions for complex logic.
   - Example: Create a custom `SecurityExpressionRoot` to add methods like `hasCustomPermission()`.
3. **Performance Considerations**:
   - Method security uses AOP, which introduces overhead due to proxy creation.
   - Minimize complex SpEL expressions in high-throughput methods to avoid performance bottlenecks.
