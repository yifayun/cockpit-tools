//! Cursor's Electron safeStorage wrapper for auth tokens.
//!
//! Cursor 3.27+ stores `cursorAuth/accessToken` and
//! `cursorAuth/refreshToken` as `cursor-safe-storage:v1:` followed by a
//! base64 encoded Chromium `v10` AES-256-GCM payload. On Windows the AES key
//! is stored in Cursor's `Local State` file and protected with DPAPI.

use std::path::Path;

pub const CURSOR_SAFE_STORAGE_PREFIX: &str = "cursor-safe-storage:v1:";

pub fn is_sealed(value: &str) -> bool {
    value.starts_with(CURSOR_SAFE_STORAGE_PREFIX)
}

pub fn decrypt_if_needed(value: &str, data_root: &Path) -> Result<String, String> {
    if !is_sealed(value) {
        return Ok(value.to_string());
    }

    decrypt_sealed(value, data_root)
}

pub fn encrypt_if_needed(value: &str, data_root: &Path) -> Result<String, String> {
    if is_sealed(value) {
        return Ok(value.to_string());
    }

    encrypt_sealed(value, data_root)
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::CURSOR_SAFE_STORAGE_PREFIX;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::{Aead, AeadCore, OsRng};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::{engine::general_purpose, Engine as _};
    use serde_json::Value;
    use std::path::Path;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

    const V10_PREFIX: &[u8] = b"v10";

    fn dpapi_decrypt(encrypted: &[u8]) -> Result<Vec<u8>, String> {
        unsafe {
            let mut input = CRYPT_INTEGER_BLOB {
                cbData: encrypted.len() as u32,
                pbData: encrypted.as_ptr() as *mut u8,
            };
            let mut output = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };

            CryptUnprotectData(&mut input, None, None, None, None, 0, &mut output)
                .map_err(|_| "Cursor DPAPI 解密失败".to_string())?;

            let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            LocalFree(HLOCAL(output.pbData as *mut _));
            Ok(result)
        }
    }

    fn load_encryption_key(data_root: &Path) -> Result<Vec<u8>, String> {
        let path = data_root.join("Local State");
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("读取 Cursor Local State 失败({}): {}", path.display(), e))?;
        let json: Value = serde_json::from_str(&content)
            .map_err(|e| format!("解析 Cursor Local State 失败: {}", e))?;
        let encoded = json
            .get("os_crypt")
            .and_then(|value| value.get("encrypted_key"))
            .and_then(Value::as_str)
            .ok_or_else(|| "Cursor Local State 缺少 os_crypt.encrypted_key".to_string())?;
        let encrypted = general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("解码 Cursor encrypted_key 失败: {}", e))?;

        if encrypted.len() <= 5 || &encrypted[..5] != b"DPAPI" {
            return Err("Cursor encrypted_key 不是 DPAPI 格式".to_string());
        }

        let key = dpapi_decrypt(&encrypted[5..])?;
        if key.len() != 32 {
            return Err(format!(
                "Cursor DPAPI 解出的 AES key 长度异常: {}",
                key.len()
            ));
        }
        Ok(key)
    }

    fn decrypt_v10(key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted.len() < 3 + 12 + 16 || &encrypted[..3] != V10_PREFIX {
            return Err("Cursor safeStorage 数据不是有效的 v10 AES-GCM 格式".to_string());
        }

        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        let nonce = Nonce::from_slice(&encrypted[3..15]);
        cipher
            .decrypt(nonce, &encrypted[15..])
            .map_err(|_| "Cursor safeStorage AES-GCM 解密失败".to_string())
    }

    fn encrypt_v10(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| "Cursor safeStorage AES-GCM 加密失败".to_string())?;

        let mut result = Vec::with_capacity(3 + 12 + ciphertext.len());
        result.extend_from_slice(V10_PREFIX);
        result.extend_from_slice(nonce.as_slice());
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub(super) fn decrypt_sealed(value: &str, data_root: &Path) -> Result<String, String> {
        let encoded = value
            .strip_prefix(CURSOR_SAFE_STORAGE_PREFIX)
            .ok_or_else(|| "Cursor safeStorage 前缀不匹配".to_string())?;
        let encrypted = general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("解码 Cursor safeStorage token 失败: {}", e))?;
        let key = load_encryption_key(data_root)?;
        let plaintext = decrypt_v10(&key, &encrypted)?;
        String::from_utf8(plaintext)
            .map_err(|_| "Cursor safeStorage 解密结果不是有效 UTF-8".to_string())
    }

    pub(super) fn encrypt_sealed(value: &str, data_root: &Path) -> Result<String, String> {
        let key = load_encryption_key(data_root)?;
        let encrypted = encrypt_v10(&key, value.as_bytes())?;
        Ok(format!(
            "{}{}",
            CURSOR_SAFE_STORAGE_PREFIX,
            general_purpose::STANDARD.encode(encrypted)
        ))
    }
}

#[cfg(target_os = "windows")]
fn decrypt_sealed(value: &str, data_root: &Path) -> Result<String, String> {
    windows_impl::decrypt_sealed(value, data_root)
}

#[cfg(target_os = "windows")]
fn encrypt_sealed(value: &str, data_root: &Path) -> Result<String, String> {
    windows_impl::encrypt_sealed(value, data_root)
}

#[cfg(not(target_os = "windows"))]
fn decrypt_sealed(_value: &str, _data_root: &Path) -> Result<String, String> {
    Err("Cursor safeStorage 解密目前仅支持 Windows".to_string())
}

#[cfg(not(target_os = "windows"))]
fn encrypt_sealed(value: &str, _data_root: &Path) -> Result<String, String> {
    // Preserve the pre-existing plaintext behavior on platforms whose native
    // safeStorage backend is not implemented by this module yet.
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::{decrypt_if_needed, is_sealed};
    use std::path::Path;

    #[test]
    fn plaintext_tokens_are_left_unchanged() {
        let token = "header.payload.signature";
        assert!(!is_sealed(token));
        assert_eq!(
            decrypt_if_needed(token, Path::new("unused")),
            Ok(token.to_string())
        );
    }
}
