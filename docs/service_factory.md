# Service Architecture & Composition Documentation

## 1. Architectural Overview

The core architecture is built on the **Service-Oriented Orchestration** pattern. It separates raw data access (Stores) from business logic (Services). This design is optimized for Rust’s ownership model and the requirement for high-integrity, transactional business operations.

### Core Principles

- **Request-Scoped Lifetime**: Services are instantiated on a per-request basis. This ensures that every request is isolated, preventing state leakage and ensuring a fresh `CoreCtx` (User context, Tracing, etc.) is always used.
- **Atomic Store Sharing**: All services share an `Arc<StoreManager<D>>`. This allows every service to access the same database connection pool and, critically, the same transaction context.
- **Logic Centralization**: Business invariants (e.g., "An account must be verified to perform X") live exclusively in the Service layer, never in the Store or Controller.

---

## 2. Service Composition Patterns

### Vertical Composition (Hydration)

This pattern is used to transform flat database rows into rich, relational Core models.

- **Mechanism**: A Service uses its internal Store to fetch a record, then calls other Services to fetch related entities.
- **Example**: `MembershipService` calls `AccountService` and `WorkspaceService` to turn `account_id` and `workspace_id` into full domain objects.

### Horizontal Orchestration (Cross-Domain)

Used for complex workflows that involve multiple distinct domains.

- **Mechanism**: An orchestration method coordinates multiple service calls within a single transaction.
- **Example**: A "Workspace Onboarding" flow that creates an Account, then a Workspace, then a Membership in one atomic operation.

---

## 3. Dependency Injection & The Service Factory

To manage the creation of request-scoped services, a **Service Factory** is used. It acts as the "Registry of Dependencies."

### The Role of the Factory

1.  **Encapsulation**: It hides the complexity of service construction (e.g., cloning `Arc` pointers).
2.  **Service-to-Service Injection**: It allows a service to be created with its required dependencies already satisfied (e.g., injecting `AccountService` into `AuthService`).
3.  **Lazy Creation**: Only the services required for the specific request path are instantiated.

---

## 4. Circular Dependencies & Statelessness

In this architecture, circular dependencies (e.g., Service A needing Service B, while Service B needs Service A) are **not** an issue.

- **On-Demand Instantiation**: Because services are lightweight "logic wrappers" holding `Arc` pointers to stores, they can be instantiated "on the fly" inside method calls.
- **Stack Allocation**: Child services are typically created on the stack during a method call and dropped immediately after. There are no long-lived heap-allocated reference loops.

---

## 5. Transactional Integrity (DbExecutor)

Maintaining ACID properties across multiple service calls is handled by the **Database Executor (`D`)** carried within the `CoreCtx`.

### The Transaction Flow

1.  A transaction is initiated (typically at the Service Orchestrator or Controller level).
2.  The transaction-bound `CoreCtx` is passed to the first Service.
3.  The same `CoreCtx` is passed to subsequent Services.
4.  All services execute their SQL against the same transaction.
5.  If any service returns an `Err`, the transaction is rolled back globally.

---

## 6. Service Implementation Standard

Every core service should follow this structural template:

1.  **Constructor**: A `new` method that accepts `Arc<StoreManager<D>>` and any required child Services.
2.  **Validator**: Integration with `AuthValidator` via `CoreCtx` to enforce RBAC/ACL at the start of every business logic method.
3.  **Scoping**: Explicitly handling `workspace_id` or `account_id` filtering to ensure data isolation.
4.  **Transformation**: Using `.into()` or explicit mapping functions to convert Store rows into Core models.

```rust
// Standard Service Signature
pub struct ExampleService<D: DbExecutor> {
    sm: Arc<StoreManager<D>>,
    other_svc: OtherService<D>, // Injected dependency
}
```

## 7. Dependency Injection Strategy: Injection vs. Location

The system utilizes **Constructor Injection** rather than the **Service Locator** pattern.

### Decision: Specificity over Uniformity

While passing the `ServiceFactory` to all services would provide a uniform interface, we opt to pass specific dependencies (StoreManager, CacheManager, and specific child Services) for the following reasons:

1. **Explicit Dependencies**: Struct definitions clearly state what a service requires, improving code readability and maintainability.
2. **Testability**: Services can be unit-tested in isolation by providing mock implementations of specific dependencies rather than a full factory.
3. **Reduced Coupling**: Services remain focused on their specific domain and its immediate neighbors, preventing the "God Object" anti-pattern where every service knows about every other service.

### Refined Service Signature

```rust
pub struct MembershipService<D: DbExecutor> {
    sm: Arc<StoreManager<D>>,
    account_svc: AccountService<D>,
    workspace_svc: WorkspaceService<D>,
}
```

## 8. Service Trait Architecture

The system uses a **decomposed trait pattern** to define service capabilities. This ensures type safety and prevents "interface bloat."

### Capability-Based Design

Instead of a single "God Trait" for CRUD, we split responsibilities into specific capability traits:

- **CoreModelCreateService**: Handles entity instantiation and persistence.
- **CoreModelDescribeService**: Handles single-entity retrieval and hydration.
- **CoreModelListService**: Handles collection queries, filtering, and pagination.
- **CoreModelUpdateService**: Handles partial or full entity mutations.
- **CoreModelDeleteService**: Handles entity removal (logical or physical).

### Benefits

1. **Contract Honesty**: A service like `TokenService` can implement `Create` and `Describe` without being forced to implement a non-existent `Update` method.
2. **Generic Bound Granularity**: Utility functions can require only the specific capability they need (e.g., `where S: CoreModelListService`).
3. **Consistent Naming**: All capability traits follow the `CoreModel[Action]Service` convention for high discoverability.
