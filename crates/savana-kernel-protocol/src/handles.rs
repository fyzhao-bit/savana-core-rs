use core::fmt;

use crate::StableCode;

macro_rules! opaque_handle {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $name([u8; 32]);

        impl $name {
            fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<opaque>)"))
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.bytes(&self.0)?;
                Ok(())
            }
        }

        impl<'bytes, C> minicbor::Decode<'bytes, C> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                let bytes = <[u8; 32]>::try_from(decoder.bytes()?).map_err(|_| {
                    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
                        .at(position)
                })?;
                Ok(Self::from_bytes(bytes))
            }
        }
    };
}

opaque_handle!(RunHandle);
opaque_handle!(ValueHandle);
opaque_handle!(ToolHandle);
opaque_handle!(PlannerTicketHandle);
opaque_handle!(PendingToolCallHandle);
opaque_handle!(ExecutionTicketHandle);

#[cfg(test)]
mod tests {
    use super::{ExecutionTicketHandle, RunHandle};

    #[test]
    fn white_box_construction_remains_opaque() {
        let run = RunHandle::from_bytes([7; 32]);
        let ticket = ExecutionTicketHandle::from_bytes([9; 32]);

        assert_eq!(format!("{run:?}"), "RunHandle(<opaque>)");
        assert_eq!(format!("{ticket:?}"), "ExecutionTicketHandle(<opaque>)");
        assert_eq!(minicbor::to_vec(run).unwrap().len(), 34);
    }
}
