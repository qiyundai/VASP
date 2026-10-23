//! Local UI/CLI controls only; the coordinator and model do not call this module.
use anyhow::{Result, bail};
use vasp_core::broker::*;
pub fn request(command: Command, expected_device: uuid::Uuid) -> Result<Response> {
    #[cfg(windows)]
    {
        let pipe = vasp_platform::broker_ipc::connect_broker()?;
        let hello: Hello = serde_json::from_slice(&pipe.read()?)?;
        if hello.schema != VERSION
            || hello.session.is_nil()
            || hello.device_id != expected_device
            || hello.policy_version == 0
        {
            bail!("Broker identity/schema does not match this endpoint");
        }
        let r = Request {
            schema: VERSION,
            session: hello.session,
            id: uuid::Uuid::new_v4(),
            device_id: expected_device,
            policy_version: hello.policy_version,
            issued_at: vasp_core::now(),
            command,
        };
        pipe.write(&serde_json::to_vec(&r)?)?;
        let response: Response = serde_json::from_slice(&pipe.read()?)?;
        if response.schema != VERSION
            || response.request_id != r.id
            || response.device_id != expected_device
            || response.policy_version != r.policy_version
            || response.automatic_blocking
            || response.active_blocks != 0
        {
            bail!("Unexpected broker response; blocking remains disabled");
        }
        pipe.write(RECEIPT_ACK)?;
        Ok(response)
    }
    #[cfg(not(windows))]
    {
        let _ = (command, expected_device);
        bail!("Windows broker unavailable");
    }
}
