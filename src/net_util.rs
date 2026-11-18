use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout, timeout_at};

/// What happened when we tried to read from a client.
#[derive(Debug, PartialEq)]
pub enum ReadOutcome {
    /// This many bytes arrived.
    Data(usize),
    /// The client closed the connection.
    Closed,
    /// The deadline passed before anything arrived.
    TimedOut,
}

/// Read some bytes, but never wait past `deadline`.
///
/// The deadline is a fixed point in time, not "n seconds from now". A client
/// that trickles in one byte at a time still runs out of time at the same
/// moment, which is what defeats slowloris attacks.
pub async fn read_with_deadline<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    deadline: Instant,
) -> std::io::Result<ReadOutcome> {
    match timeout_at(deadline, reader.read(buf)).await {
        Ok(Ok(0)) => Ok(ReadOutcome::Closed),
        Ok(Ok(n)) => Ok(ReadOutcome::Data(n)),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(ReadOutcome::TimedOut),
    }
}

/// Write all of `data`, but give up if the client stops accepting bytes
/// for longer than `limit`.
pub async fn write_all_timeout<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
    limit: Duration,
) -> std::io::Result<()> {
    match timeout(limit, writer.write_all(data)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "client stopped reading (write timed out)",
        )),
    }
}

/// Errors that are a normal part of life on the internet: clients close tabs,
/// lose signal, or give up. They deserve a quiet log line, not an alarm.
pub fn is_routine_disconnect(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        error.kind(),
        ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof | TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn soon(millis: u64) -> Instant {
        Instant::now() + Duration::from_millis(millis)
    }

    #[tokio::test]
    async fn data_that_arrives_is_returned() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(b"hello").await.unwrap();

        let mut buf = [0u8; 16];
        let outcome = read_with_deadline(&mut server, &mut buf, soon(5000))
            .await
            .unwrap();
        assert_eq!(outcome, ReadOutcome::Data(5));
        assert_eq!(&buf[..5], b"hello");
    }

    #[tokio::test]
    async fn a_closed_connection_is_reported() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);

        let mut buf = [0u8; 16];
        let outcome = read_with_deadline(&mut server, &mut buf, soon(5000))
            .await
            .unwrap();
        assert_eq!(outcome, ReadOutcome::Closed);
    }

    #[tokio::test]
    async fn silence_times_out() {
        let (_client, mut server) = tokio::io::duplex(64);

        let started = Instant::now();
        let mut buf = [0u8; 16];
        let outcome = read_with_deadline(&mut server, &mut buf, soon(50))
            .await
            .unwrap();
        assert_eq!(outcome, ReadOutcome::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(1000));
    }

    #[tokio::test]
    async fn trickling_bytes_cannot_extend_the_deadline() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        // A slowloris client: one byte every 20 ms, for about 2 seconds.
        tokio::spawn(async move {
            for _ in 0..100 {
                if client.write_all(b"x").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        let started = Instant::now();
        let deadline = started + Duration::from_millis(200);
        let mut buf = [0u8; 16];
        let mut bytes_seen = 0;

        loop {
            match read_with_deadline(&mut server, &mut buf, deadline)
                .await
                .unwrap()
            {
                ReadOutcome::Data(n) => bytes_seen += n,
                ReadOutcome::TimedOut => break,
                ReadOutcome::Closed => panic!("the slow client is still connected"),
            }
        }

        assert!(bytes_seen > 0, "some bytes should have arrived");
        assert!(
            started.elapsed() < Duration::from_millis(1000),
            "the deadline must hold even while bytes keep trickling in"
        );
    }

    #[tokio::test]
    async fn writes_to_a_reading_client_succeed() {
        let (mut writer, _reader) = tokio::io::duplex(1024);
        let result = write_all_timeout(&mut writer, &[0u8; 100], Duration::from_secs(5)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn writes_to_a_client_that_never_reads_time_out() {
        // The pipe holds only 8 bytes and nobody empties it.
        let (mut writer, _reader) = tokio::io::duplex(8);
        let error = write_all_timeout(&mut writer, &[0u8; 1000], Duration::from_millis(50))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn routine_disconnects_are_recognised() {
        use std::io::{Error, ErrorKind};
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::UnexpectedEof,
            ErrorKind::TimedOut,
        ] {
            assert!(is_routine_disconnect(&Error::from(kind)), "{kind:?}");
        }
        assert!(!is_routine_disconnect(&Error::from(
            ErrorKind::PermissionDenied
        )));
    }
}
