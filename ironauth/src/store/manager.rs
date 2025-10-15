use std::sync::Arc;

use sqlx::PgPool;

use crate::store::{
    dbx::Dbx,
    stores::{
        account::AccountStore, credential::CredentialStore, membership::MembershipStore,
        namespace::NamespaceStore, permission::PermissionStore, project::ProjectStore,
        role::RoleStore, token_blacklist::TokenBlacklistStore,
    },
    DbPool,
};

pub struct StoreManager {
    pub dbx: Arc<Dbx>,

    pub account: AccountStore,
    pub credential: CredentialStore,
    pub membership: MembershipStore,
    pub namespace: NamespaceStore,
    pub permission: PermissionStore,
    pub project: ProjectStore,
    pub role: RoleStore,
    pub token_blacklist: TokenBlacklistStore,
}

impl StoreManager {
    pub fn new(db: DbPool) -> Self {
        let dbx = Dbx::new(db);
        let dbx_c = Arc::new(dbx);
        let account = AccountStore::new(dbx_c.clone());
        let credential = CredentialStore::new(dbx_c.clone());
        let membership = MembershipStore::new(dbx_c.clone());
        let namespace = NamespaceStore::new(dbx_c.clone());
        let permission = PermissionStore::new(dbx_c.clone());
        let project = ProjectStore::new(dbx_c.clone());
        let role = RoleStore::new(dbx_c.clone());
        let token_blacklist = TokenBlacklistStore::new(dbx_c.clone());

        Self {
            dbx: dbx_c.clone(),
            account,
            credential,
            membership,
            namespace,
            permission,
            project,
            role,
            token_blacklist,
        }
    }

    pub fn dbx(&self) -> Arc<Dbx> {
        self.dbx.clone()
    }
}
