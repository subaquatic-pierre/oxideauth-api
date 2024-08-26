use actix_web::dev::ServiceResponse;
use actix_web::http::header::{HeaderValue, AUTHORIZATION};
use actix_web::{http::StatusCode, test, App};
use oxideauth::app::{new_test_app_data, register_all_services};
use oxideauth::db::queries::account::get_account_db;
use oxideauth::models::account::Principal;
use oxideauth::models::role::Role;
use oxideauth::routes::roles::{
    AssignRoleRes, AssignRolesReq, CreatePermissionsReq, CreatePermissionsRes, CreateRoleReq,
    CreateRoleRes, DeletePermissionsReq, DeleteRoleReq, DeleteRoleRes, DescribeRoleRes,
    ListPermissionsRes, RemoveRoleReq, RemoveRoleRes, UpdateRoleReq, UpdateRoleRes,
};
use oxideauth::utils::test_utils::{login_owner, setup_test_server};
use serde_json::json;
use serial_test::serial;

#[actix_web::test]
#[serial]
async fn test_create_role() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    // Prepare the request payload
    let payload = CreateRoleReq {
        name: "new_role".to_string(),
        description: Some("A test role".to_string()),
        permissions: Some(vec!["permission1".to_string(), "permission2".to_string()]),
    };

    // Make the request to create a role
    let req = test::TestRequest::post()
        .uri("/roles/create-role")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&payload)
        .to_request();

    let resp: ServiceResponse = test::call_service(&mut app, req).await;

    // Validate the response
    assert_eq!(resp.status(), StatusCode::OK);

    let body: CreateRoleRes = test::read_body_json(resp).await;

    assert_eq!(body.role.name, "new_role");
    assert_eq!(body.role.description.unwrap(), "A test role");
    assert!(body.role.permissions.contains(&"permission1".to_string()));
    assert!(body.role.permissions.contains(&"permission2".to_string()));
}

#[actix_web::test]
#[serial]
async fn test_update_role() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    // Create a role first
    let create_payload = json!({
        "name": "role_to_update",
        "description": "A role to be updated",
        "permissions": ["perm1", "perm2"]
    });

    let req: actix_http::Request = test::TestRequest::post()
        .uri("/roles/create-role")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&create_payload)
        .to_request();

    let create_resp: ServiceResponse = test::call_service(&mut app, req).await;
    assert_eq!(create_resp.status(), StatusCode::OK);

    let body: CreateRoleRes = test::read_body_json(create_resp).await;
    let role_id = body.role.id.to_string();

    // Update the role
    let update_payload = UpdateRoleReq {
        role: role_id,
        name: Some("updated_role".to_string()),
        description: Some("Updated description".to_string()),
    };

    let req = test::TestRequest::post()
        .uri("/roles/update-role")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&update_payload)
        .to_request();

    let resp: ServiceResponse = test::call_service(&mut app, req).await;
    // assert_eq!(resp.status(), StatusCode::OK);

    let body: UpdateRoleRes = test::read_body_json(resp).await;
    assert_eq!(body.role.name, "updated_role");
    assert_eq!(body.role.description.unwrap(), "Updated description");
}

#[actix_web::test]
#[serial]
async fn test_describe_role() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    // Create a role first
    let create_payload = json!({
        "name": "role_to_describe",
        "description": "A role to describe",
        "permissions": ["perm1", "perm2"]
    });

    let req = test::TestRequest::post()
        .uri("/roles/create-role")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&create_payload)
        .to_request();

    let create_resp: ServiceResponse = test::call_service(&mut app, req).await;
    assert_eq!(create_resp.status(), StatusCode::OK);

    let body: CreateRoleRes = test::read_body_json(create_resp).await;
    let role_id = body.role.id;

    // Describe the role
    let req = test::TestRequest::post()
        .uri(&format!("/roles/describe-role"))
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(json!({"role":role_id}))
        .to_request();

    let resp: ServiceResponse = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: DescribeRoleRes = test::read_body_json(resp).await;
    assert_eq!(body.role.name, "role_to_describe");
    assert_eq!(body.role.description.unwrap(), "A role to describe");
    assert!(body.role.permissions.contains(&"perm1".to_string()));
    assert!(body.role.permissions.contains(&"perm2".to_string()));
}

#[actix_web::test]
#[serial]
async fn test_delete_role() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    // Create a role first
    let create_payload = json!({
        "name": "role_to_delete",
        "description": "A role to delete",
        "permissions": ["perm1", "perm2"]
    });

    let req = test::TestRequest::post()
        .uri("/roles/create-role")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&create_payload)
        .to_request();

    let create_resp: ServiceResponse = test::call_service(&mut app, req).await;
    assert_eq!(create_resp.status(), StatusCode::OK);

    let body: CreateRoleRes = test::read_body_json(create_resp).await;
    let role_id = body.role.id;

    // Delete the role
    let delete_payload = DeleteRoleReq {
        role: role_id.to_string(),
    };

    let req = test::TestRequest::post()
        .uri("/roles/delete-role")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&delete_payload)
        .to_request();

    let resp: ServiceResponse = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: DeleteRoleRes = test::read_body_json(resp).await;
    assert_eq!(body.deleted_role, "role_to_delete".to_string());
}

#[actix_web::test]
#[serial]
async fn test_assign_roles() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    // Create a role first
    let create_payload = json!({
        "name": "role_to_assign",
        "description": "A role to assign",
        "permissions": ["perm1", "perm2"]
    });

    let req = test::TestRequest::post()
        .uri("/roles/create-role")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&create_payload)
        .to_request();

    let create_resp: ServiceResponse = test::call_service(&mut app, req).await;
    assert_eq!(create_resp.status(), StatusCode::OK);

    let body: CreateRoleRes = test::read_body_json(create_resp).await;
    let role_id = body.role.id;

    // Assign the role to an account (assuming account_id is available)
    let account = get_account_db(&data.db, "viewer@email.com").await.unwrap();

    let assign_payload = AssignRolesReq {
        account: account.id(),
        roles: vec![role_id.to_string()],
    };

    let req = test::TestRequest::post()
        .uri("/roles/assign-roles")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&assign_payload)
        .to_request();

    let resp: ServiceResponse = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let mut roles = vec![];
    for r in body["account"]["roles"].as_array().unwrap().iter() {
        let id = r["id"].as_str().unwrap().to_string();
        roles.push(id)
    }

    assert!(roles.contains(&role_id.to_string()));
}

#[actix_web::test]
#[serial]
async fn test_remove_roles() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    // Assuming a role and account exist, assign a role first
    let role_name = "viewer";
    // Assign the role to an account (assuming account_id is available)
    let account = get_account_db(&data.db, "viewer@email.com").await.unwrap();

    // Simulate assigning the role to the account (you might need a separate test for this)
    // After assigning the role, now test removing it
    let remove_payload = RemoveRoleReq {
        account: account.id.to_string(),
        roles: vec![role_name.to_string()],
    };

    let req = test::TestRequest::post()
        .uri("/roles/remove-roles")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&remove_payload)
        .to_request();

    let resp: ServiceResponse = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // let body: RemoveRoleRes = test::read_body_json(resp).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let mut roles = vec![];
    for r in body["account"]["roles"].as_array().unwrap().iter() {
        let id = r["id"].as_str().unwrap().to_string();
        roles.push(id)
    }

    assert!(!roles.contains(&role_name.to_string()));
}

#[actix_web::test]
#[serial]
async fn test_create_permissions() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    let create_payload = CreatePermissionsReq {
        permissions: vec!["perm1".to_string(), "perm2".to_string()],
    };

    let req = test::TestRequest::post()
        .uri("/roles/create-permissions")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&create_payload)
        .to_request();

    let resp: ServiceResponse = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: CreatePermissionsRes = test::read_body_json(resp).await;
    assert!(body.created_permissions.contains(&"perm1".to_string()));
    assert!(body.created_permissions.contains(&"perm2".to_string()));
}

#[actix_web::test]
#[serial]
async fn test_list_permissions() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    let req = test::TestRequest::get()
        .uri("/roles/list-permissions")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .to_request();

    let resp: ServiceResponse = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: ListPermissionsRes = test::read_body_json(resp).await;
    assert!(body.permissions.len() > 0); // Check that permissions exist
}

#[actix_web::test]
#[serial]
async fn test_delete_permissions() {
    let data = new_test_app_data().await;
    let mut app = setup_test_server().await;

    // Login as the owner to get the authorization token
    let login_res = login_owner(&mut app).await;
    let token = login_res["token"].as_str().unwrap();
    let value = format!("Bearer {token}");

    let delete_payload = DeletePermissionsReq {
        permissions: vec!["perm1".to_string()],
    };

    let req = test::TestRequest::post()
        .uri("/roles/delete-permissions")
        .insert_header((AUTHORIZATION, HeaderValue::from_str(&value).unwrap()))
        .set_json(&delete_payload)
        .to_request();

    let resp: ServiceResponse = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
