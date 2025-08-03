## 🧰 1. Spring Boot Maven Plugin

-   **Purpose**: Creates an **executable fat JAR** with all dependencies and embedded server (e.g., Tomcat).
-   **vs Default Maven**:
    -   **Default Maven**: Creates a plain JAR (code only, no dependencies).
    -   **Spring Boot Plugin**: Repackages JAR to include dependencies and launcher (`java -jar app.jar` works).
-   **Output**:
    -   `app.jar` (executable).
    -   `app.jar.original` (original plain JAR).
-   **POM Configuration**:

    ```xml
    <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
    </plugin>
    ```

    **Key Benefit**: No external server needed; app is self-contained.

---

🚀 2. @SpringBootApplication Annotation

-   **Purpose**: Marks the main class as the entry point of the Spring Boot app.
-   **Combines**:
    -   `@SpringBootConfiguration`: Marks class as a configuration source.
    -   `@EnableAutoConfiguration`: Auto-configures based on classpath (e.g., web, JPA).
    -   `@ComponentScan`: Scans for `@Component`, `@Service`, `@Repository`, `@Controller` in the package.

-   **Example**:

    ```java
    @SpringBootApplication
    public class SpringbootrecipiesApplication {
        public static void main(String[] args) {
            SpringApplication.run(SpringbootrecipiesApplication.class, args);
        }
    }
    ```

    **Key Point**: Single annotation to bootstrap the entire app.

---

🧱 3. Bean Configuration

-   **Beans**: Objects managed by Spring’s IoC container.
-   **Two Ways to Define**:
    1.  **Stereotype Annotations** (Auto-detected via `@ComponentScan`):
        -   `@Component`: General-purpose bean.
        -   `@Service`: Business logic.
        -   `@Repository`: Data access layer.
        -   `@Controller`/`@RestController`: Web layer.
    2.  **Using @Bean in @Configuration Class**:
        -   Manual bean creation with full control.

-   **Example**:

    ```java
    @Configuration
    public class AppConfig {
        @Bean
        public Calculator calculator(List<Operation> ops) {
            return new Calculator(ops);
        }
    }
    ```

    **Key Insight**: Spring auto-injects dependencies (e.g., `List<Operation>` gets all implementations).

---

🔧 4. Externalized Configuration

-   **Purpose**: Decouple configuration from code to avoid rebuilding JAR.
-   **Sources & Precedence** (Highest to Lowest):
    1.  Command-line arguments: `java -jar app.jar --server.port=9090`.
    2.  `spring.config.location`: Explicit file path (e.g., `file:./config/`).
    3.  External `application.properties`/`application-{profile}.properties` (next to JAR).
    4.  Internal `application.properties` (in `src/main/resources`).
    5.  `@PropertySource` (custom files, e.g., `classpath:custom-database.properties`).

-   **Key Techniques**:
    -   **Profiles**: `--spring.profiles.active=dev` → loads `application-dev.properties`.
    -   **External Files**: Place `application.properties` in JAR’s directory → overrides internal.
    -   **Custom Files**:
        -   Use `@PropertySource("classpath:custom-database.properties")`.
        -   Or `spring.config.name=custom` to load `custom.properties`.
    -   **Command-line Overrides**: `java -jar app.jar --a=12` → highest precedence.

-   **Example**:

    ```java
    @PropertySource("classpath:custom-database.properties")
    public class SpringbootrecipiesApplication {
        @Value("${a:100}")
        private int a; // Default 100 if not found
    }
    ```

    **Key Benefit**: No rebuild needed; supports environment-specific config (dev, prod).

---

📝 5. Logging with SLF4J + Logback

-   **Default Setup**: Spring Boot uses SLF4J with Logback (no extra dependencies).
-   **How to Use**:

    ```java
    import org.slf4j.Logger;
    import org.slf4j.LoggerFactory;

    @Component
    public class Calculator {
        private static final Logger log = LoggerFactory.getLogger(Calculator.class);

        public int calculate(int a, int b, char op) {
            log.info("Calculating: {} {} {}", a, op, b);
            // return result; // Assuming 'result' is defined elsewhere
            return 0; // Placeholder for compilation
        }
    }
    ```

-   **Log Levels**: TRACE, DEBUG, INFO, WARN, ERROR.
-   **Configure in `application.properties`**:

    ```properties
    # Set log levels
    logging.level.com.rajan=INFO
    logging.level.com.rajan.springbootrecipies.Calculator=DEBUG

    # Log to file
    logging.file.name=app.log

    # Console format
    logging.pattern.console=%d{HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n
    ```

-   **Best Practices**:
    -   Use parameterized logging: `log.info("Value: {}", x)`.
    -   Avoid `System.out.println()` (no control, poor performance).
    -   Use `@Slf4j` (Lombok) to reduce boilerplate.

---

💡 6. Your Code: Key Features

-   **Project**: Calculator app demonstrating dependency injection and strategy pattern.
-   **Structure**:
    -   Interface: `Operation` with `apply()` and `validOps()`.
    -   Implementations: `AdditionOperation`, `MultiplicationOperation` (both `@Component`).
    -   Service: `Calculator` with `List<Operation>` injection.
    -   Main Class: `SpringbootrecipiesApplication` with `@SpringBootApplication`.

-   **Key Features**:
    -   **Dependency Injection**: `List<Operation>` auto-injects all implementations.
    -   **Configuration**: Uses `@Value` to inject properties (`a`, `b`, `message`).
    -   **Custom Properties**: Loads `custom-database.properties` via `@PropertySource`.
    -   **Startup Logic**: Uses `ApplicationRunner` to run code at startup.
    -   **Logging**: Added `Logger` in main class (e.g., `logger.warn("opps...")`).

-   **Example**:

    ```java
    import org.slf4j.Logger;
    import org.slf4j.LoggerFactory;
    import org.springframework.beans.factory.annotation.Value;
    import org.springframework.boot.ApplicationRunner;
    import org.springframework.boot.SpringApplication;
    import org.springframework.boot.autoconfigure.SpringBootApplication;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.PropertySource;

    @SpringBootApplication
    @PropertySource("classpath:custom-database.properties")
    public class SpringbootrecipiesApplication {
        private static final Logger logger = LoggerFactory.getLogger(SpringbootrecipiesApplication.class);

        @Value("${a:100}")
        private int a;

        @Value("${b:200}") // Assuming 'b' is also a property for the example
        private int b;

        @Value("${message:default message}") // Assuming 'message' is a property
        private String message;

        public static void main(String[] args) {
            SpringApplication.run(SpringbootrecipiesApplication.class, args);
        }

        @Bean
        ApplicationRunner applicationRunner(Calculator calculator) {
            return (args) -> {
                logger.warn("opps something went wrong {}", message);
                calculator.calculate(a, b, '*'); // Assuming calculate method uses 'a', 'b', and '*'
            };
        }
    }
    ```

---

🎯 Interview Tips

-   **Auto-Configuration**: "Spring Boot auto-configures based on classpath dependencies."
-   **External Config**: "External properties avoid JAR rebuilds."
-   **Fat JAR**: "Includes embedded server, no WAR needed."
-   **Beans**: "Managed by IoC container via `@Component` or `@Bean`."
-   **Logging**: "Use SLF4J with parameterized messages for performance."
-   **Precedence**: "Command-line arguments override all other config sources."

---


## 7. `@ConfigurationProperties` (Type-Safe Configuration)

**Why:**  
Better alternative to `@Value` for grouping related configs.

**How:**

```java
@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties {
    private int a;
    private int b;
    private String message;
    // getters and setters
}
```

```properties
app.a=10
app.b=20
app.message=Hello
```

**Benefits:**
- Cleaner than scattering multiple `@Value` fields.
- Supports validation (`@Validated`, `@NotNull`, etc.).
- Handles nested configs (objects, lists).

---

## 🧪 8. Profiles with `@Profile`

**Use Case:**  
Load specific beans only for certain environments (e.g., dev, prod).

```java
@Component
@Profile("dev")
public class DevEmailSender implements EmailSender {
    // dev-only logic
}

@Component
@Profile("prod")
public class ProdEmailSender implements EmailSender {
    // production logic
}
```

**Activate Profile:**
- Command line: `--spring.profiles.active=dev`
- Or in `application.properties`:  
  `spring.profiles.active=dev`

---

## 🔁 9. Lifecycle Hooks: `@PostConstruct`, `@PreDestroy`

**Purpose:**  
Initialize or clean up resources.

```java
@Component
public class MyBean {
    @PostConstruct
    public void init() {
        System.out.println("Initialized");
    }

    @PreDestroy
    public void cleanup() {
        System.out.println("Cleaned up");
    }
}
```

---

## 🔍 10. Spring Boot DevTools

**Use Case:**  
Auto-restart on code changes and LiveReload in browser.

**How to Use:**

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-devtools</artifactId>
    <scope>runtime</scope>
</dependency>
```

> **Tip:** Only use in development, not production.

---

## 🧩 11. Auto-Configuration Debugging

- **Command:** `--debug` (on startup)
- **Purpose:** Logs which auto-configurations are applied or skipped.

---

## 🛠 12. Disabling Auto-Configuration (Fine-grained Control)

**Use Case:**  
Avoid unwanted auto-configuration.

```java
@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
public class MyApp { ... }
```
