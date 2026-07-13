use std::io::{Read, Write};

pub const IPC_MAGIC: [u8; 4] = *b"CTAL";
pub const IPC_VERSION: u8 = 1;
pub const MAX_FRAME_PAYLOAD: usize = 64 * 1024;
const HEADER_LENGTH: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    AgentHello = 1,
    LaunchGrant = 2,
    Challenge = 3,
    IntegrityReport = 4,
    Health = 5,
    Shutdown = 6,
}

impl TryFrom<u8> for MessageType {
    type Error = IpcError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::AgentHello),
            2 => Ok(Self::LaunchGrant),
            3 => Ok(Self::Challenge),
            4 => Ok(Self::IntegrityReport),
            5 => Ok(Self::Health),
            6 => Ok(Self::Shutdown),
            _ => Err(IpcError::UnknownMessage),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IpcError {
    #[error("I/O failure")]
    Io,
    #[error("invalid IPC magic or version")]
    InvalidHeader,
    #[error("unknown IPC message type")]
    UnknownMessage,
    #[error("IPC frame exceeds the 64 KiB payload limit")]
    TooLarge,
}

pub fn write_frame(writer: &mut impl Write, frame: &Frame) -> Result<(), IpcError> {
    if frame.payload.len() > MAX_FRAME_PAYLOAD {
        return Err(IpcError::TooLarge);
    }
    let mut header = [0_u8; HEADER_LENGTH];
    header[..4].copy_from_slice(&IPC_MAGIC);
    header[4] = IPC_VERSION;
    header[5] = frame.message_type as u8;
    header[6..].copy_from_slice(&(frame.payload.len() as u32).to_be_bytes());
    writer.write_all(&header).map_err(|_| IpcError::Io)?;
    writer.write_all(&frame.payload).map_err(|_| IpcError::Io)?;
    writer.flush().map_err(|_| IpcError::Io)
}

pub fn read_frame(reader: &mut impl Read) -> Result<Frame, IpcError> {
    let mut header = [0_u8; HEADER_LENGTH];
    reader.read_exact(&mut header).map_err(|_| IpcError::Io)?;
    if header[..4] != IPC_MAGIC || header[4] != IPC_VERSION {
        return Err(IpcError::InvalidHeader);
    }
    let message_type = MessageType::try_from(header[5])?;
    let length = u32::from_be_bytes(header[6..].try_into().expect("fixed header")) as usize;
    if length > MAX_FRAME_PAYLOAD {
        return Err(IpcError::TooLarge);
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).map_err(|_| IpcError::Io)?;
    Ok(Frame {
        message_type,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_round_trips() {
        let expected = Frame {
            message_type: MessageType::Challenge,
            payload: vec![1, 2, 3],
        };
        let mut bytes = vec![];
        write_frame(&mut bytes, &expected).unwrap();
        assert_eq!(read_frame(&mut Cursor::new(bytes)).unwrap(), expected);
    }

    #[test]
    fn rejects_oversize_unknown_and_truncated_frames() {
        assert_eq!(
            write_frame(
                &mut vec![],
                &Frame {
                    message_type: MessageType::Health,
                    payload: vec![0; MAX_FRAME_PAYLOAD + 1],
                },
            ),
            Err(IpcError::TooLarge)
        );
        let mut unknown = [0_u8; HEADER_LENGTH];
        unknown[..4].copy_from_slice(&IPC_MAGIC);
        unknown[4] = IPC_VERSION;
        unknown[5] = 99;
        assert_eq!(
            read_frame(&mut Cursor::new(unknown)),
            Err(IpcError::UnknownMessage)
        );
        assert_eq!(read_frame(&mut Cursor::new([0_u8; 4])), Err(IpcError::Io));
    }
}
