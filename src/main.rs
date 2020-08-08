#![no_std]
#![no_main]
use redbpf_macros::{program, xdp};
use redbpf_probes::bindings::*;
use redbpf_probes::xdp::{Transport, XdpAction, XdpContext};
use redbpf_probes::helpers::gen::bpf_redirect;

program!(0xFFFFFFFE, "GPL");

#[xdp]
pub extern "C" fn trace_http(ctx: XdpContext) -> XdpAction {
    if let Some(transport @ Transport::UDP(udp)) = ctx.transport() {
        if transport.dest() != 19132 {
            return XdpAction::Pass;
        }
        unsafe {
            (*udp).dest = 29132
        }
        bpf_redirect(1, 0); // ifindex = '1' for loopback interface. Need to figure out how to lookup...
        return XdpAction::Redirect
    }
    XdpAction::Pass
}