use anyhow::{bail, Context, Result};
use certael_agent_protocol::{
    verify_branding_manifest, BrandingManifestClaimsV1, SignedBrandingManifestV1,
    VerificationKeyRing,
};
use png::{Decoder, Limits, Transformations};
use prost::Message;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{BufReader, Cursor, Read},
    path::{Component, Path, PathBuf},
};

const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_ICON_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_HERO_FILE_BYTES: u64 = 12 * 1024 * 1024;
const MAX_ICON_DECODED_BYTES: usize = 16 * 1024 * 1024;
const MAX_HERO_DECODED_BYTES: usize = 48 * 1024 * 1024;
const MIN_ICON_DIMENSION: u32 = 32;
const MAX_ICON_DIMENSION: u32 = 2048;
const MIN_HERO_WIDTH: u32 = 640;
const MIN_HERO_HEIGHT: u32 = 320;
const MAX_HERO_WIDTH: u32 = 3840;
const MAX_HERO_HEIGHT: u32 = 2160;

#[derive(Clone, Debug)]
pub struct VerifiedBrandingImage {
    pub path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct VerifiedBranding {
    pub claims: BrandingManifestClaimsV1,
    pub icon: VerifiedBrandingImage,
    pub hero: Option<VerifiedBrandingImage>,
}

pub struct InstalledBranding {
    pub signed: SignedBrandingManifestV1,
    pub icon: Vec<u8>,
    pub hero: Option<Vec<u8>>,
}

pub fn verify_install(
    signed_manifest_path: &Path,
    branding_root: &Path,
    keys: &VerificationKeyRing,
    registration_id: &str,
    game_id: &str,
    now_unix: i64,
) -> Result<InstalledBranding> {
    let manifest = read_regular(signed_manifest_path, MAX_MANIFEST_BYTES)
        .context("signed branding manifest is invalid")?;
    let signed = SignedBrandingManifestV1::decode(manifest.as_slice())
        .context("signed branding manifest is malformed")?;
    if signed.encode_to_vec() != manifest {
        bail!("signed branding manifest is not canonical");
    }
    let claims = verify_branding_manifest(&signed, keys, now_unix)
        .context("signed branding manifest was rejected")?;
    validate_binding(&claims, registration_id, game_id)?;
    let root = branding_root
        .canonicalize()
        .context("branding asset root is unavailable")?;
    if !root.is_dir() || !safe_relative(&claims.icon_relative_path) {
        bail!("branding asset root or icon path is invalid");
    }
    let icon_path = root
        .join(&claims.icon_relative_path)
        .canonicalize()
        .context("signed branding icon is unavailable")?;
    if !icon_path.starts_with(&root) {
        bail!("signed branding icon escapes its asset root");
    }
    let icon =
        read_regular(&icon_path, MAX_ICON_FILE_BYTES).context("signed branding icon is invalid")?;
    if Sha256::digest(&icon).as_slice() != claims.icon_sha256 {
        bail!("signed branding icon digest does not match");
    }
    verify_png(&icon, PngRole::Icon)?;
    let hero = if claims.hero_relative_path.is_empty() {
        None
    } else {
        let hero_path = root
            .join(&claims.hero_relative_path)
            .canonicalize()
            .context("signed branding hero is unavailable")?;
        if !hero_path.starts_with(&root) {
            bail!("signed branding hero escapes its asset root");
        }
        let bytes = read_regular(&hero_path, MAX_HERO_FILE_BYTES)
            .context("signed branding hero is invalid")?;
        if Sha256::digest(&bytes).as_slice() != claims.hero_sha256 {
            bail!("signed branding hero digest does not match");
        }
        verify_png(&bytes, PngRole::Hero)?;
        Some(bytes)
    };
    Ok(InstalledBranding { signed, icon, hero })
}

pub fn verify_stored(
    signed_bytes: &[u8],
    icon_path: &Path,
    hero_path: &Path,
    keys: &VerificationKeyRing,
    registration_id: &str,
    game_id: &str,
    now_unix: i64,
) -> Result<VerifiedBranding> {
    if signed_bytes.is_empty() || signed_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        bail!("stored branding manifest size is invalid");
    }
    let signed = SignedBrandingManifestV1::decode(signed_bytes)
        .context("stored branding manifest is malformed")?;
    if signed.encode_to_vec() != signed_bytes {
        bail!("stored branding manifest is not canonical");
    }
    let claims = verify_branding_manifest(&signed, keys, now_unix)
        .context("stored branding manifest was rejected")?;
    validate_binding(&claims, registration_id, game_id)?;
    let icon =
        read_regular(icon_path, MAX_ICON_FILE_BYTES).context("stored branding icon is invalid")?;
    if Sha256::digest(&icon).as_slice() != claims.icon_sha256 {
        bail!("stored branding icon digest does not match");
    }
    verify_png(&icon, PngRole::Icon)?;
    let hero = if claims.hero_relative_path.is_empty() {
        if hero_path.exists() {
            bail!("stored branding has an unsigned hero image");
        }
        None
    } else {
        let bytes = read_regular(hero_path, MAX_HERO_FILE_BYTES)
            .context("stored branding hero is invalid")?;
        if Sha256::digest(&bytes).as_slice() != claims.hero_sha256 {
            bail!("stored branding hero digest does not match");
        }
        verify_png(&bytes, PngRole::Hero)?;
        Some(VerifiedBrandingImage {
            path: hero_path.to_path_buf(),
        })
    };
    Ok(VerifiedBranding {
        claims,
        icon: VerifiedBrandingImage {
            path: icon_path.to_path_buf(),
        },
        hero,
    })
}

pub fn decode_icon_rgba(path: &Path) -> Result<(Vec<u8>, u32, u32)> {
    let bytes = read_regular(path, MAX_ICON_FILE_BYTES)?;
    decode_png(&bytes, true, PngRole::Icon)
}

pub fn decode_hero_rgba(path: &Path) -> Result<(Vec<u8>, u32, u32)> {
    let bytes = read_regular(path, MAX_HERO_FILE_BYTES)?;
    decode_png(&bytes, true, PngRole::Hero)
}

fn validate_binding(
    claims: &BrandingManifestClaimsV1,
    registration_id: &str,
    game_id: &str,
) -> Result<()> {
    if claims.registration_id != registration_id || claims.game_id != game_id {
        bail!("branding manifest is bound to another game registration");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PngRole {
    Icon,
    Hero,
}

fn verify_png(bytes: &[u8], role: PngRole) -> Result<(u32, u32)> {
    let (_, width, height) = decode_png(bytes, false, role)?;
    Ok((width, height))
}

fn decode_png(bytes: &[u8], retain_pixels: bool, role: PngRole) -> Result<(Vec<u8>, u32, u32)> {
    let maximum_decoded = match role {
        PngRole::Icon => MAX_ICON_DECODED_BYTES,
        PngRole::Hero => MAX_HERO_DECODED_BYTES,
    };
    let mut decoder = Decoder::new_with_limits(
        BufReader::new(Cursor::new(bytes)),
        Limits {
            bytes: maximum_decoded,
        },
    );
    decoder.set_transformations(
        Transformations::EXPAND | Transformations::STRIP_16 | Transformations::ALPHA,
    );
    let mut reader = decoder
        .read_info()
        .context("branding icon is not a valid PNG")?;
    let info = reader.info();
    let (width, height) = info.size();
    let dimensions_valid = match role {
        PngRole::Icon => {
            width >= MIN_ICON_DIMENSION
                && height >= MIN_ICON_DIMENSION
                && width <= MAX_ICON_DIMENSION
                && height <= MAX_ICON_DIMENSION
                && width == height
        }
        PngRole::Hero => {
            width >= MIN_HERO_WIDTH
                && height >= MIN_HERO_HEIGHT
                && width <= MAX_HERO_WIDTH
                && height <= MAX_HERO_HEIGHT
                && (1.5..=2.4).contains(&(width as f64 / height as f64))
        }
    };
    if !dimensions_valid || info.animation_control.is_some() {
        bail!("branding PNG dimensions or animation are unsupported");
    }
    let output_size = reader
        .output_buffer_size()
        .context("branding PNG decoded size is invalid")?;
    if output_size == 0 || output_size > maximum_decoded {
        bail!("branding PNG decoded size exceeds its limit");
    }
    let mut output = vec![0; output_size];
    let frame = reader
        .next_frame(&mut output)
        .context("branding PNG pixel data is invalid")?;
    output.truncate(frame.buffer_size());
    if !matches!(frame.color_type, png::ColorType::Rgb | png::ColorType::Rgba) {
        bail!("branding PNG must decode to RGB or RGBA");
    }
    if retain_pixels {
        match frame.color_type {
            png::ColorType::Rgba => {}
            png::ColorType::Rgb => {
                let mut rgba = Vec::with_capacity(width as usize * height as usize * 4);
                for pixel in output.chunks_exact(3) {
                    rgba.extend_from_slice(&[pixel[0], pixel[1], pixel[2], 255]);
                }
                output = rgba;
            }
            _ => unreachable!("color type was checked above"),
        }
    } else {
        output.clear();
    }
    Ok((output, width, height))
}

fn safe_relative(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= 512
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn read_regular(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        bail!("file is not a bounded regular file");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("file exceeds its size limit");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use certael_agent_protocol::{VerificationKey, BRANDING_DOMAIN, PROTOCOL_VERSION};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut output = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut output, width, height);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            writer
                .write_image_data(&vec![0x80; width as usize * height as usize * 4])
                .unwrap();
        }
        output
    }

    #[test]
    fn verifies_signed_local_png_and_rejects_digest_substitution() {
        let directory = tempfile::tempdir().unwrap();
        let icon = png(64, 64);
        let hero = png(1280, 720);
        std::fs::create_dir(directory.path().join("icons")).unwrap();
        std::fs::write(directory.path().join("icons/game.png"), &icon).unwrap();
        std::fs::write(directory.path().join("icons/hero.png"), &hero).unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let keys = VerificationKeyRing::new(vec![VerificationKey {
            key_id: "publisher".into(),
            key: key.verifying_key(),
            not_before_unix: 1_600_000_000,
            not_after_unix: 1_800_000_000,
            revoked: false,
        }])
        .unwrap();
        let claims = BrandingManifestClaimsV1 {
            protocol_version: PROTOCOL_VERSION,
            registration_id: "sample-production".into(),
            game_id: "sample-game".into(),
            display_name: "Sample Game".into(),
            publisher_name: "Sample Publisher".into(),
            icon_relative_path: "icons/game.png".into(),
            icon_sha256: Sha256::digest(&icon).to_vec(),
            not_before_unix: 1_699_999_900,
            expires_at_unix: 1_700_003_600,
            hero_relative_path: "icons/hero.png".into(),
            hero_sha256: Sha256::digest(&hero).to_vec(),
        };
        let claim_bytes = claims.encode_to_vec();
        let signed = SignedBrandingManifestV1 {
            claims: claim_bytes.clone(),
            signature: key
                .sign(&[BRANDING_DOMAIN, &claim_bytes].concat())
                .to_bytes()
                .to_vec(),
            key_id: "publisher".into(),
        };
        let manifest = directory.path().join("branding.pb");
        std::fs::write(&manifest, signed.encode_to_vec()).unwrap();
        let verified = verify_install(
            &manifest,
            directory.path(),
            &keys,
            "sample-production",
            "sample-game",
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(verify_png(&verified.icon, PngRole::Icon).unwrap(), (64, 64));
        assert!(verified.hero.is_some());

        std::fs::write(directory.path().join("icons/game.png"), png(32, 32)).unwrap();
        assert!(verify_install(
            &manifest,
            directory.path(),
            &keys,
            "sample-production",
            "sample-game",
            1_700_000_000,
        )
        .is_err());
    }
}
