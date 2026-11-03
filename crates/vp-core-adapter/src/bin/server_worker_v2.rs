//! Dedicated managed server-v2 worker; never accepts the v1 WorkerConfig wire.
fn main() {
    vp_product_core_adapter::managed::server_worker_v2::main_v2();
}
