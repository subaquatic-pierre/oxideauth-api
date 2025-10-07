# Rust API Architecture: A Summary

This document outlines a robust, layered architecture for building scalable and maintainable APIs in Rust. The design prioritizes separation of concerns, type safety, and reusability.

---

## Core Architecture: A Layered Approach

The architecture is divided into distinct layers, each with a single responsibility. This decouples the core business logic from the delivery mechanism (e.g., HTTP), allowing for greater flexibility and testability.

```mermaid
graph TD
    subgraph "External Interfaces"
        HTTP_Requests[("Web & API Clients")]
    end

    HTTP_Requests --> HTTP_Handlers

    subgraph "Application Delivery (The 'Adapter')"
        HTTP_Handlers[HTTP Handler Layer]
    end

    HTTP_Handlers --> RPC_Facade

    subgraph "Application Core"
        RPC_Facade[RPC Interface Layer (The 'Port')]
        Controller_Layer[Controller Layer]
        Store_Layer[Data Access Layer]
    end

    RPC_Facade --> Controller_Layer
    Controller_Layer --> Store_Layer

    subgraph "Data Persistence"
        Store_Layer --> Database[(Database)]
    end
```

- **HTTP Handler Layer:** Translates HTTP requests and responses. Knows about web-specific concerns like status codes and headers.
- **RPC Interface Layer:** Defines the application's public contract in a transport-agnostic way (e.g., `create_account(...)`). This is the single entry point to the core logic.
- **Controller Layer:** Orchestrates business logic and use cases, often coordinating multiple stores.
- **Store Layer:** Manages data persistence and queries for a single entity.

---

## The Data Access Layer (DAL): A Trait-Based Design

The DAL is built on a "Foundation + Capability" pattern using traits.

### Foundational Trait: `Store`

A single base trait defines the core identity of a data store. The compiler enforces this contract for every store.

```rust
pub trait Store {
    // The Iden enum for the store's table and columns.
    type TableIden: 'static + Iden;

    // Guaranteed constants for the table and primary key.
    const TABLE_NAME: Self::TableIden;
    const TABLE_PK: Self::TableIden;

    // The type of the Primary Key (e.g., Uuid, i64).
    type IdKind: ToString + Into<sea_query::Value> + Send;

    // The Rust struct that represents a database row.
    type Row: for<'r> FromRow<'r, PgRow> + Unpin + Send + Sync;
}
```

### Capability Traits

Additional traits grant specific abilities (CRUD, Joins, etc.) to a store.

```rust
// Example: grants the `.create()` method
pub trait Create where Self: Store {
    type CreateStoreParams: HasSeaFields + Send;
    async fn create(&self, ctx: &StoreCtx, data: Self::CreateStoreParams) -> Result<Self::Row>;
}

// Example: grants the `.get_joined()` method for one-to-many relationships
pub trait JoinOneToManyStore where Self: Store {
    // ... metadata for the related table and join condition
    async fn get_joined(&self, ctx: &StoreCtx, id: Self::IdKind) -> Result<Self::JoinedRow>;
}
```
