# Spring Boot RestTemplate & Retry - Study Notes


## ResponseBodyEmitter vs SseEmitter

| Feature | ResponseBodyEmitter | SseEmitter |
|---------|-------------------|------------|
| **Protocol** | Plain HTTP/1.1 (chunked) | Server-Sent Events (SSE) |
| **Media-Type** | Any (JSON, text, binary) | Must be `text/event-stream` |
| **Front-End API** | Manual fetch + ReadableStream | Native EventSource |
| **Browser Support** | All modern browsers | IE/Edge ≤ 15 need polyfill |
| **Message Framing** | Custom (raw JSON, text, binary) | SSE spec: `data: …\n\n` |
| **Auto Reconnection** | ❌ (manual coding) | ✅ EventSource retries by default |
| **Events/IDs/Comments** | ❌ | ✅ `event: myEvent\ndata: …\nid: 123\n\n` |
| **Duplex Communication** | ❌ (still one-way) | ❌ (still one-way) |

### When to Use Which
- **ResponseBodyEmitter**: Custom media-type, controlled client code, no SSE features needed
- **SseEmitter**: Browser-native SSE, automatic reconnection, named events with IDs

### Code Examples

#### ResponseBodyEmitter (JSON Lines)
```java
@GetMapping("/stream")
public ResponseBodyEmitter stream() {
    ResponseBodyEmitter emitter = new ResponseBodyEmitter();
    executor.execute(() -> {
        try {
            for (int i = 0; i < 10; i++) {
                emitter.send(Map.of("id", i), MediaType.APPLICATION_JSON);
                Thread.sleep(1000);
            }
            emitter.complete();
        } catch (Exception e) {
            emitter.completeWithError(e);
        }
    });
    return emitter;
}
```

#### SseEmitter (SSE Protocol)
```java
@GetMapping(value = "/sse", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
public SseEmitter sse() {
    SseEmitter emitter = new SseEmitter();
    executor.execute(() -> {
        try {
            for (int i = 0; i < 10; i++) {
                emitter.send(SseEmitter.event()
                    .id(String.valueOf(i))
                    .name("priceUpdate")
                    .data(Map.of("price", 100 + i)));
                Thread.sleep(1000);
            }
            emitter.complete();
        } catch (Exception e) {
            emitter.completeWithError(e);
        }
    });
    return emitter;
}
```

### JavaScript Client Comparison

#### ResponseBodyEmitter Client
```javascript
const res = await fetch('/stream');
const reader = res.body.getReader();
const decoder = new TextDecoder();
while (true) {
  const { value, done } = await reader.read();
  if (done) break;
  console.log(JSON.parse(decoder.decode(value)));
}
```

#### SseEmitter Client
```javascript
const source = new EventSource('/sse');
source.addEventListener('priceUpdate', e => {
  console.log(JSON.parse(e.data));
});
```

## RestTemplate Configuration with Retry

### Complete Working Example

```java
@SpringBootApplication
public class SpringBootRecipesApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringBootRecipesApplication.class, args);
    }
}

// Logging Interceptor
class LoggingInterceptor implements ClientHttpRequestInterceptor {
    private static final Logger logger = LoggerFactory.getLogger(LoggingInterceptor.class);

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, 
            ClientHttpRequestExecution execution) throws IOException {
        // Log request details
        logger.info("Request URL: {}", request.getURI());
        logger.info("Request Method: {}", request.getMethod());
        logger.info("Request Headers: {}", request.getHeaders());
        if (body.length > 0) {
            logger.info("Request Body: {}", new String(body, StandardCharsets.UTF_8));
        }

        // Execute request
        ClientHttpResponse response = execution.execute(request, body);

        // Log response details safely
        logger.info("Response Status: {}", response.getStatusCode());
        logger.info("Response Headers: {}", response.getHeaders());
        String responseBody = StreamUtils.copyToString(response.getBody(), StandardCharsets.UTF_8);
        logger.info("Response Body: {}", responseBody);

        // Return wrapped response to preserve stream
        return new BufferedClientHttpResponseWrapper(response, responseBody.getBytes(StandardCharsets.UTF_8));
    }
}

// Response wrapper to preserve input stream
class BufferedClientHttpResponseWrapper implements ClientHttpResponse {
    private final ClientHttpResponse response;
    private final byte[] body;

    public BufferedClientHttpResponseWrapper(ClientHttpResponse response, byte[] body) {
        this.response = response;
        this.body = body;
    }

    @Override
    public HttpStatus getStatusCode() throws IOException {
        return response.getStatusCode();
    }

    @Override
    public String getStatusText() throws IOException {
        return response.getStatusText();
    }

    @Override
    public void close() {
        response.close();
    }

    @Override
    public InputStream getBody() throws IOException {
        return new ByteArrayInputStream(body);
    }

    @Override
    public HttpHeaders getHeaders() {
        return response.getHeaders();
    }

    @Override
    public int getRawStatusCode() throws IOException {
        return response.getRawStatusCode();
    }
}
```

### Configuration Classes

```java
@Configuration
class RestConfig {
    @Bean
    RestTemplate restTemplate(RestTemplateBuilder restTemplateBuilder) {
        RestTemplate restTemplate = restTemplateBuilder.build();
        restTemplate.getInterceptors().add(new LoggingInterceptor());
        return restTemplate;
    }

    @Bean
    RetryRegistry retryRegistry() {
        RetryConfig retryConfig = RetryConfig.custom()
                .maxAttempts(3)
                .waitDuration(Duration.ofSeconds(1))
                .retryOnResult(c -> true) // For practice - retry on all responses
                // .retryExceptions(HttpServerErrorException.class) // Production - retry only on 5xx errors
                .build();
        return RetryRegistry.of(retryConfig);
    }
}
```

### Controller with Retry Logic

```java
@RestController
class PostController {
    private static final Logger logger = LoggerFactory.getLogger(PostController.class);
    private final RestTemplate restTemplate;
    private final Retry retry;

    public PostController(RestTemplate restTemplate, RetryRegistry retryRegistry) {
        this.restTemplate = restTemplate;
        this.retry = retryRegistry.retry("http-api-retry");
    }

    @GetMapping("/")
    public ResponseEntity<String> getPosts() {
        try {
            // GET with getForObject
            String resForObject = Retry.decorateSupplier(retry, () -> {
                logger.info("Attempting getForObject call");
                return restTemplate.getForObject("https://httpbin.org/get", String.class);
            }).get(); // Important: .get() executes the retry logic

            // GET with getForEntity  
            ResponseEntity<String> resForEntity = Retry.decorateSupplier(retry, () -> {
                logger.info("Attempting getForEntity call");
                return restTemplate.getForEntity("https://httpbin.org/get", String.class);
            }).get();

            // GET with exchange (more control)
            HttpHeaders headers = new HttpHeaders();
            headers.add("Custom-Header", "value");
            HttpEntity<?> entity = new HttpEntity<>(null, headers);
            
            ResponseEntity<String> resForExchange = Retry.decorateSupplier(retry, () -> {
                logger.info("Attempting exchange call");
                return restTemplate.exchange("https://httpbin.org/get", HttpMethod.GET, entity, String.class);
            }).get();

            String result = String.format(
                "getForObject: %s\ngetForEntity: %s\nexchange: %s",
                resForObject, resForEntity.getBody(), resForExchange.getBody()
            );
            
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            logger.error("Error fetching posts: {}", e.getMessage());
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }

    @PostMapping("/")
    public ResponseEntity<String> addPost() {
        try {
            logger.info("POST request initiated");
            String url = "https://httpbin.org/post";
            
            ResponseEntity<String> response = Retry.decorateSupplier(retry, () -> {
                logger.info("Attempting postForEntity call");
                ResponseEntity<String> res = restTemplate.postForEntity(
                    url, Map.of("hello", "world", "timestamp", System.currentTimeMillis()), String.class
                );
                logger.info("POST attempt completed with status: {}", res.getStatusCode());
                return res;
            }).get(); // Critical: Must call .get() to execute
            
            logger.info("Final POST response received");
            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            logger.error("Error posting data: {}", e.getMessage());
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }
}
```

## Logging Interceptor

### Key Points
- **Purpose**: Log all HTTP requests and responses centrally
- **Safe Response Reading**: Use `StreamUtils.copyToString()` to avoid consuming the InputStream
- **Response Wrapper**: Create a buffered wrapper to preserve the response stream for the application
- **Production Ready**: Use SLF4J instead of `System.out.println`

### Common Pitfalls
❌ **Wrong**: `response.getBody()` directly in logging (consumes stream)
✅ **Right**: `StreamUtils.copyToString(response.getBody(), StandardCharsets.UTF_8)`

## Retry Configuration

### Basic Retry Settings
```java
RetryConfig retryConfig = RetryConfig.custom()
    .maxAttempts(3)                    // Try up to 3 times
    .waitDuration(Duration.ofMillis(1000))  // Wait 1s between attempts
    .retryExceptions(HttpServerErrorException.class)  // Retry on 5xx errors
    .build();
```

### Advanced Retry Settings
```java
RetryConfig retryConfig = RetryConfig.custom()
    .maxAttempts(5)
    .waitDuration(Duration.ofMillis(500))
    .backoffMultiplier(2)              // Exponential backoff: 500ms, 1000ms, 2000ms
    .retryExceptions(IOException.class, HttpServerErrorException.class)
    .ignoreExceptions(HttpClientErrorException.class)  // Don't retry 4xx errors
    .build();
```

### Practice vs Production
| Setting | Practice | Production |
|---------|----------|------------|
| **Retry Condition** | `.retryOnResult(c -> true)` | `.retryExceptions(HttpServerErrorException.class)` |
| **Max Attempts** | 3-5 (to see behavior) | 2-3 (avoid overload) |
| **Wait Duration** | 1s (fast testing) | 500ms-2s (realistic) |
| **Backoff** | Optional | Recommended (exponential) |

## Best Practices & Tips

### ✅ Do's
- **Use .get()**: Always call `.get()` on `Retry.decorateSupplier()` to execute
- **Return ResponseEntity**: Use proper REST responses instead of `void`
- **Safe Logging**: Use `StreamUtils.copyToString()` for response body logging
- **SLF4J Logging**: Replace `System.out.println` with proper logging
- **Exception Handling**: Wrap retry calls in try-catch blocks
- **Specific Retries**: In production, retry only on transient failures (5xx)

### ❌ Don'ts  
- **Missing .get()**: `Retry.decorateSupplier(retry, () -> {...})` without `.get()`
- **Consuming Streams**: Reading `response.getBody()` directly in interceptors
- **Void Returns**: Using `void` return types in `@RestController`
- **Retry on 4xx**: Don't retry client errors (400, 401, 404, etc.)
- **No Backoff**: Always use delays/backoff to avoid overwhelming servers

### Testing Retry Behavior
```java
@Test
void testRetryOnFailure() {
    MockRestServiceServer mockServer = MockRestServiceServer.createServer(restTemplate);
    
    mockServer.expect(requestTo("https://httpbin.org/post"))
              .andRespond(withServerError()); // Simulate 500 error
    
    // This should retry 3 times
    controller.addPost();
    
    mockServer.verify(); // Verify 3 attempts were made
}
```

### Dependencies Required
```xml
<dependency>
    <groupId>io.github.resilience4j</groupId>
    <artifactId>resilience4j-spring-boot3</artifactId>
    <version>2.2.0</version>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

### Common Interview Questions

**Q: Why use retries?**
A: Handle transient failures (network issues, temporary server overload). Makes applications more resilient.

**Q: When should you retry?**
A: On 5xx server errors, network timeouts, connection issues. Never on 4xx client errors.

**Q: How to avoid overwhelming servers?**
A: Use exponential backoff, limit max attempts, add jitter to retry timing.

**Q: Why use interceptors?**  
A: Centralized logging, authentication, request/response modification across all HTTP calls.

