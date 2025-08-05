# Spring Boot Learning Notes - Part 2
*Advanced Spring MVC, Testing, Error Handling & Internationalization*

---

## 🌐 1. Spring MVC Controllers

### Basic REST Controller Setup

**`@RestController`** = `@Controller` + `@ResponseBody`
- Automatically serializes return values to JSON/XML
- No need for explicit `@ResponseBody` on each method

```java
@RestController
@RequestMapping("/api/todos")
public class TodoController {
    
    @Autowired
    private TodoService todoService;
    
    @GetMapping
    public List<Todo> getAllTodos() {
        return todoService.getTodos();
    }
    
    @PostMapping
    public Todo createTodo(@RequestBody Todo todo) {
        return todoService.save(todo);
    }
    
    @GetMapping("/{id}")
    public Todo getTodoById(@PathVariable Long id) {
        return todoService.findById(id);
    }
}
```

**Key Benefits:**
- Clean separation of concerns
- Automatic JSON serialization via Jackson
- Built-in content negotiation
- RESTful URL mapping

---

## 🧪 2. Testing Controllers with Mockito

### Unit Testing Setup

```java
@ExtendWith(MockitoExtension.class)
class TodoControllerTest {

    @Mock
    private TodoService todoService;

    @InjectMocks
    private TodoController todoController;

    @BeforeEach
    public void setup() {
        when(todoService.getTodos()).thenReturn(
            List.of(new Todo(1, 1, "Test Todo", false))
        );
    }

    @Test
    void shouldReturnTodos() {
        // When
        List<Todo> todos = todoController.getTodos();
        
        // Then
        assertEquals(1, todos.size());
        assertEquals("Test Todo", todos.get(0).title());
        verify(todoService).getTodos();
    }
}
```

### Integration Testing with MockMvc

```java
@SpringBootTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class TodoControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void shouldCreateTodo() throws Exception {
        mockMvc.perform(post("/api/todos")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"title\":\"New Todo\",\"completed\":false}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.title").value("New Todo"));
    }
}
```

**Testing Best Practices:**
- Use `@Mock` for dependencies, `@InjectMocks` for tested class
- Verify method calls with `verify()`
- Use `MockMvc` for integration testing
- Test both success and error scenarios

---

## ⚠️ 3. Exception Handling in Spring MVC

### Traditional Error Handling (View-Based)

For view-based applications, create error templates:
- `error.html` (generic error page)
- `404.html` (not found)
- `500.html` (server error)

### Modern REST Error Handling with Problem Details (RFC 7807)

#### Custom Error Attributes (Legacy Approach)

```java
@Component
public class CustomErrorAttributes extends DefaultErrorAttributes {
    
    @Override
    public Map<String, Object> getErrorAttributes(WebRequest webRequest,
            ErrorAttributeOptions options) {
        Map<String, Object> errorAttributes = new HashMap<>();
        Throwable error = getError(webRequest);
        
        String message = error != null ? error.getMessage() : "Something went wrong";
        errorAttributes.put("message", message);
        errorAttributes.put("timestamp", new Date());
        
        return errorAttributes;
    }
}
```

#### Problem Details Approach (Recommended)

```java
@RestController
@RequestMapping("/api")
public class DemoController {

    // 1. Traditional exception
    @GetMapping("/legacy")
    public String legacy() {
        throw new RuntimeException("Legacy boom!");
    }

    // 2. Explicit ProblemDetail response
    @GetMapping("/problem")
    public ProblemDetail problem() {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST, "Item ID must be positive");
        pd.setTitle("Invalid Identifier");
        pd.setType(URI.create("https://api.example.com/errors/invalid-id"));
        pd.setInstance(URI.create("/problem"));
        return pd;
    }

    // 3. Validation endpoint
    @PostMapping("/validation")
    public String validation(@Valid @RequestBody TodoDto dto) {
        return "Success";
    }
}

record TodoDto(@NotBlank String title) {}
```

#### Global Exception Handler

```java
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException ex) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        pd.setTitle("Validation Failed");
        pd.setType(URI.create("https://api.example.com/errors/validation"));

        // Add field-specific errors
        Map<String, List<String>> fieldErrors = ex.getFieldErrors()
            .stream()
            .collect(Collectors.groupingBy(
                FieldError::getField,
                Collectors.mapping(FieldError::getDefaultMessage, 
                    Collectors.toList())));
        
        pd.setProperty("fieldErrors", fieldErrors);
        return pd;
    }

    @ExceptionHandler(RuntimeException.class)
    public ProblemDetail handleRuntimeException(RuntimeException ex) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        pd.setTitle("Internal Server Error");
        pd.setDetail(ex.getMessage());
        return pd;
    }
}
```

**Problem Details Benefits:**
- Standardized error format (RFC 7807)
- Machine-readable error responses
- Consistent error structure across APIs
- Better client-side error handling

---

## 🌍 4. Internationalization (i18n)

### Basic Setup

#### 1. Create Message Files

**`src/main/resources/messages.properties` (Default - English):**
```properties
greeting.message=Hello World
error.validation=Validation failed
user.welcome=Welcome, {0}!
```

**`src/main/resources/messages_hi.properties` (Hindi):**
```properties
greeting.message=नमस्ते दुनिया
error.validation=सत्यापन असफल
user.welcome=स्वागत है, {0}!
```

**`src/main/resources/messages_es.properties` (Spanish):**
```properties
greeting.message=Hola Mundo
error.validation=Validación fallida
user.welcome=¡Bienvenido, {0}!
```

#### 2. Configure Application Properties

```properties
# Message source configuration
spring.messages.basename=messages
spring.messages.encoding=UTF-8
spring.messages.cache-duration=3600
```

#### 3. Create Internationalized Controller

```java
@RestController
public class GreetController {

    private final MessageSource messageSource;

    public GreetController(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @GetMapping("/greet")
    public String greet(Locale locale) {
        // Locale automatically resolved from Accept-Language header
        return messageSource.getMessage("greeting.message", null, locale);
    }

    @GetMapping("/welcome/{name}")
    public String welcome(@PathVariable String name, Locale locale) {
        // Using parameters in messages
        return messageSource.getMessage("user.welcome", new Object[]{name}, locale);
    }
}
```

### Advanced Locale Resolution

#### Default: Accept-Language Header
Spring Boot uses `AcceptHeaderLocaleResolver` by default.

#### Session-Based Locale Resolution

```java
@Configuration
public class LocaleConfig {

    @Bean
    public LocaleResolver localeResolver() {
        SessionLocaleResolver resolver = new SessionLocaleResolver();
        resolver.setDefaultLocale(Locale.ENGLISH);
        return resolver;
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor interceptor = new LocaleChangeInterceptor();
        interceptor.setParamName("lang"); // URL parameter: ?lang=hi
        return interceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(localeChangeInterceptor());
    }
}
```

#### Cookie-Based Locale Resolution

```java
@Bean
public LocaleResolver localeResolver() {
    CookieLocaleResolver resolver = new CookieLocaleResolver();
    resolver.setDefaultLocale(Locale.ENGLISH);
    resolver.setCookieName("user-locale");
    resolver.setCookieMaxAge(3600); // 1 hour
    return resolver;
}
```

### Testing Different Locales

```bash
# English (default)
curl -H "Accept-Language: en" http://localhost:8080/greet
# Response: Hello World

# Hindi
curl -H "Accept-Language: hi" http://localhost:8080/greet
# Response: नमस्ते दुनिया

# Spanish
curl -H "Accept-Language: es" http://localhost:8080/greet
# Response: Hola Mundo

# With session-based resolver
curl http://localhost:8080/greet?lang=hi
```

**i18n Best Practices:**
- Always provide default messages
- Use UTF-8 encoding for non-ASCII characters
- Keep message keys descriptive
- Use parameters for dynamic content
- Test with different locales

---

## 🚀 5. Embedded Server Configuration

### Default: Apache Tomcat
Spring Boot uses Tomcat by default, but you can easily switch to other embedded servers.

### Switching to Jetty

#### 1. Update `pom.xml`

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <exclusions>
            <!-- Exclude default Tomcat -->
            <exclusion>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-tomcat</artifactId>
            </exclusion>
        </exclusions>
    </dependency>
    
    <!-- Add Jetty -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-jetty</artifactId>
    </dependency>
</dependencies>
```

#### 2. Optional Jetty Configuration

```properties
# Server configuration
server.port=8080
server.servlet.context-path=/api

# Jetty-specific settings
server.jetty.connection-idle-timeout=30000
server.jetty.max-http-form-post-size=200000
```

### Switching to Undertow

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
    <exclusions>
        <exclusion>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-tomcat</artifactId>
        </exclusion>
    </exclusions>
</dependency>

<!-- Add Undertow -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-undertow</artifactId>
</dependency>
```

### Server Performance Comparison

| Server | Memory Usage | Startup Time | Throughput | Best For |
|--------|-------------|--------------|------------|----------|
| **Tomcat** | Medium | Medium | Good | General purpose, mature |
| **Jetty** | Low | Fast | Good | Lightweight, embedded |
| **Undertow** | Low | Very Fast | Excellent | High performance, NIO |

**Choosing the Right Server:**
- **Tomcat**: Production-ready, extensive documentation
- **Jetty**: Lightweight, good for microservices
- **Undertow**: Best performance, reactive applications

---

## 🎯 Interview Quick Reference

### Spring MVC
- **"What's the difference between @Controller and @RestController?"**
  - `@RestController` = `@Controller` + `@ResponseBody`
  - Automatically serializes responses to JSON/XML

### Testing
- **"How do you test Spring controllers?"**
  - Unit tests: `@Mock` services, `@InjectMocks` controllers
  - Integration tests: `@SpringBootTest` with `MockMvc`

### Error Handling
- **"How do you handle errors in Spring Boot REST APIs?"**
  - Use `@RestControllerAdvice` with `@ExceptionHandler`
  - Modern approach: Return `ProblemDetail` (RFC 7807)
  - Provides standardized error responses

### Internationalization
- **"How do you support multiple languages in Spring Boot?"**
  - Use `MessageSource` with `messages.properties` files
  - Spring auto-resolves locale from `Accept-Language` header
  - Support session/cookie-based locale resolution

### Embedded Servers
- **"Can you change the embedded server in Spring Boot?"**
  - Yes, exclude default Tomcat and add Jetty/Undertow dependency
  - Spring Boot auto-configures the available server
  - Choose based on performance and memory requirements

---

## 🔗 Additional Resources

- [Spring MVC Documentation](https://docs.spring.io/spring-framework/docs/current/reference/html/web.html)
- [Spring Boot Testing Guide](https://spring.io/guides/gs/testing-web/)
- [RFC 7807 Problem Details](https://tools.ietf.org/html/rfc7807)
- [Spring Internationalization](https://spring.io/blog/2021/11/29/spring-tips-internationalization)
