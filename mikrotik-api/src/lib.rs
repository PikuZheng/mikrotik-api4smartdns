pub mod mikrotik_api;
pub mod plugin;
pub mod smartdns;

use ctor::ctor;
use ctor::dtor;
use plugin::*;
use smartdns::*;

fn lib_init_ops() {
    let ops: Box<dyn SmartdnsOperations> = Box::new(MikrotikPluginImpl::new());
    unsafe {
        let plugin_addr = std::ptr::addr_of_mut!(PLUGIN);
        (*plugin_addr).set_operation(ops);
    }
}

fn lib_deinit_ops() {
    unsafe {
        let plugin_addr = std::ptr::addr_of_mut!(PLUGIN);
        (*plugin_addr).clear_operation();
    }
}

#[ctor]
fn lib_init() {
    lib_init_ops();
}

#[dtor]
fn lib_deinit() {
    lib_deinit_ops();
}
