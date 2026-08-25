//! One-shot SPAKE2 authentication for compact human pairing codes.

use std::io;

use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::time::{timeout_at, wall_now};
use pakery_core::crypto::{CpaceGroup, Hash};
use pakery_crypto::{
    HkdfSha512, HmacSha512, P256Group, SPAKE2_P256_M_COMPRESSED, SPAKE2_P256_N_COMPRESSED,
    Sha512Hash,
};
use pakery_spake2::{
    PartyA, PartyAState, PartyB, PartyBState, Spake2Ciphersuite, Spake2Error, Spake2Output,
};
use rand_core::{OsRng, UnwrapErr};
use rift_protocol::{
    PAIRING_CONFIRMATION_FRAME_BYTES, PAIRING_SHARE_FRAME_BYTES, PairingCode, PairingConfirmation,
    PairingFrameError, PairingShare, Role,
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const SENDER_IDENTITY: &[u8] = b"RIFT v1 sender";
const RECEIVER_IDENTITY: &[u8] = b"RIFT v1 receiver";
const PAKE_AAD_DOMAIN: &[u8] = b"RIFT v1 compact pairing";
const PAIRING_TIMEOUT_NANOS: u64 = 10_000_000_000;

struct Rfc9382P256Sha512;

impl Spake2Ciphersuite for Rfc9382P256Sha512 {
    type Group = P256Group;
    type Hash = Sha512Hash;
    type Kdf = HkdfSha512;
    type Mac = HmacSha512;

    const NH: usize = 64;
    const M_BYTES: &'static [u8] = &SPAKE2_P256_M_COMPRESSED;
    const N_BYTES: &'static [u8] = &SPAKE2_P256_N_COMPRESSED;
}

/// Compact-code authentication failure.
#[derive(Debug, Error)]
pub enum PairingError {
    /// Ordered path failed during the bounded exchange.
    #[error("pairing path failed: {0}")]
    Io(#[from] io::Error),
    /// A peer pairing frame was malformed or cross-protocol.
    #[error(transparent)]
    Frame(#[from] PairingFrameError),
    /// RFC 9382 processing or explicit key confirmation failed.
    #[error(transparent)]
    Spake2(#[from] Spake2Error),
    /// Password-to-group processing failed.
    #[error("pairing password derivation failed: {0}")]
    Password(#[from] pakery_core::PakeError),
    /// Peer claimed the local endpoint role.
    #[error("pairing peer claimed the wrong endpoint role")]
    WrongPeerRole,
    /// The pinned ciphersuite emitted a structurally impossible length.
    #[error("pairing ciphersuite emitted an invalid fixed-width value")]
    InvalidSuiteOutput,
    /// The peer did not complete the one-round exchange within its hard bound.
    #[error("pairing exchange timed out")]
    Timeout,
}

enum PairingState {
    Sender(PartyAState<Rfc9382P256Sha512>),
    Receiver(PartyBState<Rfc9382P256Sha512>),
}

impl PairingState {
    fn finish(self, peer_share: &[u8]) -> Result<Spake2Output, Spake2Error> {
        match self {
            Self::Sender(state) => state.finish(peer_share),
            Self::Receiver(state) => state.finish(peer_share),
        }
    }
}

/// Authenticate a compact code and derive a strong Noise PSK.
///
/// Both endpoints exchange fixed-width P-256/SHA-512 SPAKE2 shares, exchange
/// and verify explicit confirmation MACs, and only then expose a domain- and
/// transcript-bound 256-bit secret to the existing Noise handshake.
///
/// # Errors
///
/// Returns for malformed peer records, wrong words, role reflection, path
/// failure, cryptographic processing failure, or confirmation failure. Callers
/// must close the one-shot rendezvous after any error.
pub async fn establish_pairing_secret<S>(
    stream: &mut S,
    code: &PairingCode,
    role: Role,
) -> Result<Zeroizing<[u8; 32]>, PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let deadline = wall_now().saturating_add_nanos(PAIRING_TIMEOUT_NANOS);
    timeout_at(deadline, establish_pairing_secret_inner(stream, code, role))
        .await
        .map_err(|_| PairingError::Timeout)?
}

async fn establish_pairing_secret_inner<S>(
    stream: &mut S,
    code: &PairingCode,
    role: Role,
) -> Result<Zeroizing<[u8; 32]>, PairingError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let password = code.password_bytes();
    let password_hash = Zeroizing::new(Sha512Hash::digest(password.as_ref()));
    let mut password_scalar = P256Group::scalar_from_wide_bytes(&password_hash)?;
    let lookup_id = code.lookup_id();
    let mut aad = [0_u8; PAKE_AAD_DOMAIN.len() + 16];
    aad[..PAKE_AAD_DOMAIN.len()].copy_from_slice(PAKE_AAD_DOMAIN);
    aad[PAKE_AAD_DOMAIN.len()..].copy_from_slice(&lookup_id);
    let mut rng = UnwrapErr(OsRng);

    let (share_bytes, state) = match role {
        Role::Sender => {
            let (share, state) = PartyA::<Rfc9382P256Sha512>::start(
                &password_scalar,
                SENDER_IDENTITY,
                RECEIVER_IDENTITY,
                &aad,
                &mut rng,
            )?;
            (share, PairingState::Sender(state))
        }
        Role::Receiver => {
            let (share, state) = PartyB::<Rfc9382P256Sha512>::start(
                &password_scalar,
                SENDER_IDENTITY,
                RECEIVER_IDENTITY,
                &aad,
                &mut rng,
            )?;
            (share, PairingState::Receiver(state))
        }
    };
    password_scalar.zeroize();

    let local_share = PairingShare {
        role,
        bytes: share_bytes
            .try_into()
            .map_err(|_| PairingError::InvalidSuiteOutput)?,
    };
    stream.write_all(&local_share.encode()).await?;
    stream.flush().await?;

    let mut peer_share_frame = [0_u8; PAIRING_SHARE_FRAME_BYTES];
    stream.read_exact(&mut peer_share_frame).await?;
    let peer_share = PairingShare::decode(&peer_share_frame)?;
    ensure_peer_role(role, peer_share.role)?;

    let output = state.finish(&peer_share.bytes)?;
    let local_confirmation = PairingConfirmation {
        role,
        bytes: output
            .confirmation_mac
            .as_slice()
            .try_into()
            .map_err(|_| PairingError::InvalidSuiteOutput)?,
    };
    stream.write_all(&local_confirmation.encode()).await?;
    stream.flush().await?;

    let mut peer_confirmation_frame = [0_u8; PAIRING_CONFIRMATION_FRAME_BYTES];
    stream.read_exact(&mut peer_confirmation_frame).await?;
    let peer_confirmation = PairingConfirmation::decode(&peer_confirmation_frame)?;
    ensure_peer_role(role, peer_confirmation.role)?;
    output.verify_peer_confirmation(&peer_confirmation.bytes)?;

    let (sender_share, receiver_share) = match role {
        Role::Sender => (&local_share.bytes, &peer_share.bytes),
        Role::Receiver => (&peer_share.bytes, &local_share.bytes),
    };
    let mut derivation = blake3::Hasher::new_derive_key("RIFT v1 SPAKE2 to Noise PSK");
    derivation.update(output.session_key.as_bytes());
    derivation.update(&lookup_id);
    derivation.update(sender_share);
    derivation.update(receiver_share);
    Ok(Zeroizing::new(*derivation.finalize().as_bytes()))
}

fn ensure_peer_role(local: Role, peer: Role) -> Result<(), PairingError> {
    let expected = match local {
        Role::Sender => Role::Receiver,
        Role::Receiver => Role::Sender,
    };
    if peer == expected {
        Ok(())
    } else {
        Err(PairingError::WrongPeerRole)
    }
}

#[cfg(test)]
mod tests {
    use asupersync::{net::TcpListener, runtime::RuntimeBuilder};
    use pakery_crypto::Spake2P256;

    use super::*;

    type P256Scalar = <P256Group as CpaceGroup>::Scalar;

    fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        let mut bytes = [0_u8; N];
        for (index, output) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *output = u8::from_str_radix(&text[offset..offset + 2], 16).unwrap();
        }
        bytes
    }

    fn p256_scalar(text: &str) -> P256Scalar {
        let mut wide = Zeroizing::new([0_u8; 64]);
        wide[32..].copy_from_slice(&decode_hex::<32>(text));
        P256Group::scalar_from_wide_bytes(wide.as_ref()).unwrap()
    }

    #[test]
    fn pinned_engine_matches_rfc_9382_appendix_b() {
        let w = p256_scalar("2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f");
        let x = p256_scalar("43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729");
        let y = p256_scalar("dcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be");
        let (share_a, state_a) =
            PartyA::<Spake2P256>::start_with_scalar(&w, &x, b"server", b"client", b"").unwrap();
        let (share_b, state_b) =
            PartyB::<Spake2P256>::start_with_scalar(&w, &y, b"server", b"client", b"").unwrap();

        assert_eq!(
            share_a,
            decode_hex::<65>(concat!(
                "04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470",
                "f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c"
            ))
        );
        assert_eq!(
            share_b,
            decode_hex::<65>(concat!(
                "0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676",
                "d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7"
            ))
        );

        let output_a = state_a.finish(&share_b).unwrap();
        let output_b = state_b.finish(&share_a).unwrap();
        let expected_key = decode_hex::<16>("0e0672dc86f8e45565d338b0540abe69");
        assert_eq!(output_a.session_key.as_bytes(), expected_key);
        assert_eq!(output_b.session_key.as_bytes(), expected_key);
        assert_eq!(
            output_a.confirmation_mac,
            decode_hex::<32>("58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0")
        );
        assert_eq!(
            output_b.confirmation_mac,
            decode_hex::<32>("d3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b")
        );
        output_a
            .verify_peer_confirmation(&output_b.confirmation_mac)
            .unwrap();
        output_b
            .verify_peer_confirmation(&output_a.confirmation_mac)
            .unwrap();
    }

    #[test]
    fn matching_codes_derive_the_same_noise_secret() {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let handle = runtime.handle();
        let (sender_secret, receiver_secret) = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let receiver = handle.clone().spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let code = "4827-lumeko".parse::<PairingCode>().unwrap();
                establish_pairing_secret(&mut stream, &code, Role::Receiver)
                    .await
                    .unwrap()
            });
            let mut sender_stream = asupersync::net::TcpStream::connect(address).await.unwrap();
            let code = "4827-lumeko".parse::<PairingCode>().unwrap();
            let sender = establish_pairing_secret(&mut sender_stream, &code, Role::Sender)
                .await
                .unwrap();
            (sender, receiver.await)
        });
        assert_eq!(*sender_secret, *receiver_secret);
    }

    #[test]
    fn wrong_word_fails_explicit_confirmation() {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let handle = runtime.handle();
        let (sender_failed, receiver_failed) = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let receiver = handle.clone().spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let code = "4827-lameko".parse::<PairingCode>().unwrap();
                establish_pairing_secret(&mut stream, &code, Role::Receiver)
                    .await
                    .is_err()
            });
            let mut sender_stream = asupersync::net::TcpStream::connect(address).await.unwrap();
            let code = "4827-lumeko".parse::<PairingCode>().unwrap();
            let sender_failed = establish_pairing_secret(&mut sender_stream, &code, Role::Sender)
                .await
                .is_err();
            (sender_failed, receiver.await)
        });
        assert!(sender_failed);
        assert!(receiver_failed);
    }

    #[test]
    fn reflected_sender_role_fails_before_key_derivation() {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let handle = runtime.handle();
        let (left_failed, right_failed) = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let right = handle.clone().spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let code = "4827-lumeko".parse::<PairingCode>().unwrap();
                establish_pairing_secret(&mut stream, &code, Role::Sender)
                    .await
                    .is_err()
            });
            let mut stream = asupersync::net::TcpStream::connect(address).await.unwrap();
            let code = "4827-lumeko".parse::<PairingCode>().unwrap();
            let left_failed = establish_pairing_secret(&mut stream, &code, Role::Sender)
                .await
                .is_err();
            (left_failed, right.await)
        });
        assert!(left_failed);
        assert!(right_failed);
    }
}
