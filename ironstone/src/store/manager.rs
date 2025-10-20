use std::sync::Arc;

use crate::store::{
    dbx::{DbExecutor, PgDbx},
    init::PgPool,
    stores::{
        account::AccountStore, credential::CredentialStore, membership::MembershipStore,
        namespace::NamespaceStore, permission::PermissionStore, project::ProjectStore,
        role::RoleStore, token_blacklist::TokenBlacklistStore,
    },
};

pub struct StoreManager<Dbx: DbExecutor> {
    pub dbx: Arc<Dbx>,

    pub account: AccountStore<Dbx>,
    pub credential: CredentialStore<Dbx>,
    pub membership: MembershipStore<Dbx>,
    pub namespace: NamespaceStore<Dbx>,
    pub permission: PermissionStore<Dbx>,
    pub project: ProjectStore<Dbx>,
    pub role: RoleStore<Dbx>,
    pub token_blacklist: TokenBlacklistStore<Dbx>,
}

impl<Dbx: DbExecutor> StoreManager<Dbx> {
    pub fn new(dbx: Arc<Dbx>) -> Self {
        let account = AccountStore::new(dbx.clone());
        let credential = CredentialStore::new(dbx.clone());
        let membership = MembershipStore::new(dbx.clone());
        let namespace = NamespaceStore::new(dbx.clone());
        let permission = PermissionStore::new(dbx.clone());
        let project = ProjectStore::new(dbx.clone());
        let role = RoleStore::new(dbx.clone());
        let token_blacklist = TokenBlacklistStore::new(dbx.clone());

        Self {
            dbx: dbx.clone(),
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

pub trait StoreManagerTrait<Dbx: DbExecutor> {
    fn account(&self) -> &AccountStore<Dbx>;
}
