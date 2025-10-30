use jsonrpsee::RpcModule;

pub fn build_root_rpc_router() -> RpcModule<()> {
    let root_module = RpcModule::new(());
    root_module
}
