use log::*;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub struct VirtualDevice {
    transmitter: UnboundedSender<Vec<u8>>,
    receiver: UnboundedReceiver<Vec<u8>>,
}

impl VirtualDevice {
    pub fn new(
        transmitter: UnboundedSender<Vec<u8>>,
        receiver: UnboundedReceiver<Vec<u8>>,
    ) -> Self {
        VirtualDevice {
            transmitter,
            receiver,
        }
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = ReceivingToken where Self: 'a;
    type TxToken<'a> = TransmitToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        trace!("Receiving packet");
        self.receiver.try_recv().ok().map(|buff| {
            let rx = ReceivingToken { buff };
            let tx = TransmitToken {
                tx: &mut self.transmitter,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        trace!("Transmitting packet");
        let tx = TransmitToken {
            tx: &mut self.transmitter,
        };
        Some(tx)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1500;
        capabilities
    }
}

pub struct ReceivingToken {
    buff: Vec<u8>,
}

impl RxToken for ReceivingToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        debug!("Receiving a packet of len: {}", self.buff.len());
        f(&mut self.buff)
    }
}

pub struct TransmitToken<'a> {
    tx: &'a mut UnboundedSender<Vec<u8>>,
}

impl<'a> TxToken for TransmitToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buff = vec![0; len];
        let result = f(&mut buff);
        debug!("Transmitting packet of length: {}", buff.len());
        self.tx.send(buff).ok();
        result
    }
}
