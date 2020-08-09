#![no_std]
#![no_main]
#![feature(bindings_after_at)]

use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[xdp]
pub extern "C" fn trace_http(ctx: XdpContext) -> XdpResult {
    if let Ok(ref transport @ Transport::UDP(udp)) = ctx.transport() {
        if transport.dest() != 7999 {
            return XdpResult::Ok(XdpAction::Pass);
        }
        unsafe {
            (*udp).dest = 7998_u16.to_be();
            // bpf_redirect(1, 0); // ifindex = '1' for loopback interface. Need to figure out how to lookup...
        }
        // return XdpResult::Ok(XdpAction::Redirect)
    }
    XdpResult::Ok(XdpAction::Pass)
}