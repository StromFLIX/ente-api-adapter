//! Collection + file synchronisation, metadata decryption and downloads.

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::client::{EnteApiError, MuseumClient};
use crate::config::Settings;
use crate::crypto::{b64decode, decrypt_chacha, decrypt_file_stream, secretbox_open};
use crate::faces::DetectedFace;

pub const FILE_TYPE_IMAGE: i64 = 0;
pub const FILE_TYPE_VIDEO: i64 = 1;
pub const FILE_TYPE_LIVE_PHOTO: i64 = 2;

fn media_type_name(file_type: i64) -> &'static str {
    match file_type {
        FILE_TYPE_IMAGE => "image",
        FILE_TYPE_VIDEO => "video",
        FILE_TYPE_LIVE_PHOTO => "live_photo",
        _ => "unknown",
    }
}

#[derive(Clone)]
pub struct Album {
    pub id: i64,
    pub name: String,
    pub key: Vec<u8>,
    pub is_deleted: bool,
}

#[derive(Clone)]
pub struct ImageFile {
    pub id: i64,
    pub collection_id: i64,
    pub album_name: String,
    pub key: Vec<u8>,
    pub decryption_header: String,
    pub file_size: Option<i64>,
    pub title: Option<String>,
    pub file_type: i64,
    pub creation_time: Option<i64>,
    pub modification_time: Option<i64>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub file_hash: Option<String>,
    pub is_deleted: bool,
    /// Detected faces (from Ente's separate "mldata" dataset), annotated with
    /// the person each face belongs to. Empty if face data is disabled or absent.
    pub faces: Vec<DetectedFace>,
    /// Dimensions of the image the face boxes are relative to.
    pub face_image_width: Option<i64>,
    pub face_image_height: Option<i64>,
}

impl ImageFile {
    pub fn media_type(&self) -> &'static str {
        media_type_name(self.file_type)
    }

    /// Distinct names of people detected in this image, in stable order.
    pub fn person_names(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut names = Vec::new();
        for face in &self.faces {
            if let Some(name) = &face.person_name {
                if seen.insert(name.clone()) {
                    names.push(name.clone());
                }
            }
        }
        names
    }

    pub fn as_json(&self, download_url: &str) -> Value {
        json!({
            "id": self.id,
            "title": self.title,
            "album": self.album_name,
            "collectionId": self.collection_id,
            "mediaType": self.media_type(),
            "fileSize": self.file_size,
            "creationTime": self.creation_time,
            "modificationTime": self.modification_time,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "hash": self.file_hash,
            // URL of the still-encrypted blob, so other apps can fetch it
            // straight from the storage backend (e.g. the S3 bucket).
            "downloadUrl": download_url,
            // Detected faces (with person names where known) from Ente's
            // separately-derived "mldata" dataset.
            "faces": self.faces.iter().map(DetectedFace::as_json).collect::<Vec<_>>(),
            // Convenience: distinct named people present in this image.
            "people": self.person_names(),
            // Dimensions the face boxes are relative to.
            "faceImageWidth": self.face_image_width,
            "faceImageHeight": self.face_image_height,
        })
    }
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn decrypt_album(raw: &Value, master_key: &[u8]) -> Result<Album, EnteApiError> {
    let enc_key = str_field(raw, "encryptedKey")
        .ok_or_else(|| EnteApiError::Decode("album missing encryptedKey".into()))?;
    let nonce = str_field(raw, "keyDecryptionNonce")
        .ok_or_else(|| EnteApiError::Decode("album missing keyDecryptionNonce".into()))?;
    let key = secretbox_open(&enc_key, &nonce, master_key)
        .map_err(|e| EnteApiError::Decode(e.to_string()))?;

    let id = raw.get("id").and_then(as_i64).unwrap_or(0);
    let mut name = str_field(raw, "name").unwrap_or_default();
    if name.is_empty() {
        if let (Some(enc_name), Some(name_nonce)) = (
            str_field(raw, "encryptedName"),
            str_field(raw, "nameDecryptionNonce"),
        ) {
            if let Ok(decoded) = secretbox_open(&enc_name, &name_nonce, &key) {
                name = String::from_utf8_lossy(&decoded).to_string();
            }
        }
    }
    if name.is_empty() {
        if let Some(magic) = raw.get("magicMetadata") {
            if let (Some(data), Some(header)) =
                (str_field(magic, "data"), str_field(magic, "header"))
            {
                if let Ok(plain) = decrypt_chacha(&data, &key, &header) {
                    if let Ok(meta) = serde_json::from_slice::<Value>(&plain) {
                        name = str_field(&meta, "name")
                            .or_else(|| str_field(&meta, "title"))
                            .unwrap_or_default();
                    }
                }
            }
        }
    }
    if name.is_empty() {
        name = format!("album-{id}");
    }

    Ok(Album {
        id,
        name,
        key,
        is_deleted: raw.get("isDeleted").and_then(Value::as_bool).unwrap_or(false),
    })
}

fn decode_metadata(attr: Option<&Value>, key: &[u8]) -> Value {
    let attr = match attr {
        Some(a) if !a.is_null() => a,
        _ => return Value::Null,
    };
    let (data, header) = match (str_field(attr, "encryptedData"), str_field(attr, "decryptionHeader")) {
        (Some(d), Some(h)) => (d, h),
        _ => return Value::Null,
    };
    match decrypt_chacha(&data, key, &header) {
        Ok(plain) => serde_json::from_slice(&plain).unwrap_or(Value::Null),
        Err(_) => Value::Null,
    }
}

fn decrypt_file(raw: &Value, album: &Album) -> Option<ImageFile> {
    let id = raw.get("id").and_then(as_i64)?;

    if raw.get("isDeleted").and_then(Value::as_bool).unwrap_or(false) {
        return Some(ImageFile {
            id,
            collection_id: album.id,
            album_name: album.name.clone(),
            key: Vec::new(),
            decryption_header: String::new(),
            file_size: None,
            title: None,
            file_type: FILE_TYPE_IMAGE,
            creation_time: None,
            modification_time: None,
            latitude: None,
            longitude: None,
            file_hash: None,
            is_deleted: true,
            faces: Vec::new(),
            face_image_width: None,
            face_image_height: None,
        });
    }

    let enc_key = str_field(raw, "encryptedKey")?;
    let nonce = str_field(raw, "keyDecryptionNonce")?;
    let file_key = secretbox_open(&enc_key, &nonce, &album.key).ok()?;

    let metadata = decode_metadata(raw.get("metadata"), &file_key);
    let pub_magic = decode_metadata(raw.get("pubMagicMetadata"), &file_key);

    let mut latitude = pub_magic
        .get("lat")
        .and_then(as_f64)
        .or_else(|| metadata.get("latitude").and_then(as_f64));
    let mut longitude = pub_magic
        .get("long")
        .and_then(as_f64)
        .or_else(|| metadata.get("longitude").and_then(as_f64));
    if latitude == Some(0.0) && longitude == Some(0.0) {
        latitude = None;
        longitude = None;
    }

    let creation = pub_magic
        .get("editedTime")
        .and_then(as_i64)
        .or_else(|| metadata.get("creationTime").and_then(as_i64));
    let title = pub_magic
        .get("editedName")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| metadata.get("title").and_then(|v| v.as_str()).map(|s| s.to_string()));

    let file_size = raw
        .get("info")
        .and_then(|i| i.get("fileSize"))
        .and_then(as_i64);

    let decryption_header = raw
        .get("file")
        .and_then(|f| f.get("decryptionHeader"))
        .and_then(|v| v.as_str())?
        .to_string();

    let file_type = metadata
        .get("fileType")
        .and_then(as_i64)
        .unwrap_or(FILE_TYPE_IMAGE);

    Some(ImageFile {
        id,
        collection_id: album.id,
        album_name: album.name.clone(),
        key: file_key,
        decryption_header,
        file_size,
        title,
        file_type,
        creation_time: creation,
        modification_time: metadata.get("modificationTime").and_then(as_i64),
        latitude,
        longitude,
        file_hash: str_field(&metadata, "hash"),
        is_deleted: false,
        faces: Vec::new(),
        face_image_width: None,
        face_image_height: None,
    })
}

pub async fn fetch_library(
    client: &MuseumClient,
    master_key: &[u8],
) -> Result<HashMap<i64, ImageFile>, EnteApiError> {
    let collections = client
        .get("/collections/v2", &[("sinceTime", "0".to_string())])
        .await?;
    let mut files: HashMap<i64, ImageFile> = HashMap::new();

    let empty = Vec::new();
    let albums = collections
        .get("collections")
        .and_then(Value::as_array)
        .unwrap_or(&empty);

    for raw_album in albums {
        let album = match decrypt_album(raw_album, master_key) {
            Ok(a) => a,
            Err(_) => continue,
        };
        if album.is_deleted {
            continue;
        }
        let mut since = 0i64;
        loop {
            let page = client
                .get(
                    "/collections/v2/diff",
                    &[
                        ("collectionID", album.id.to_string()),
                        ("sinceTime", since.to_string()),
                    ],
                )
                .await?;
            let diff = page
                .get("diff")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if diff.is_empty() {
                break;
            }
            for entry in &diff {
                if let Some(ut) = entry.get("updationTime").and_then(as_i64) {
                    since = since.max(ut);
                }
                if let Some(decrypted) = decrypt_file(entry, &album) {
                    if decrypted.is_deleted {
                        files.remove(&decrypted.id);
                    } else {
                        files.insert(decrypted.id, decrypted);
                    }
                }
            }
            if !page.get("hasMore").and_then(Value::as_bool).unwrap_or(false) {
                break;
            }
        }
    }
    Ok(files)
}

pub async fn download_image(
    client: &MuseumClient,
    settings: &Settings,
    file: &ImageFile,
) -> Result<Vec<u8>, EnteApiError> {
    let encrypted = client.get_bytes(&settings.download_url(file.id)).await?;
    let header = b64decode(&file.decryption_header)
        .map_err(|e| EnteApiError::Decode(e.to_string()))?;
    decrypt_file_stream(&encrypted, &file.key, &header)
        .map_err(|e| EnteApiError::Decode(e.to_string()))
}

pub async fn delete_file(
    client: &MuseumClient,
    file_id: i64,
    collection_id: i64,
) -> Result<(), EnteApiError> {
    client
        .post_no_content(
            "/files/trash",
            &json!({"items": [{"fileID": file_id, "collectionID": collection_id}]}),
        )
        .await
}

#[allow(clippy::too_many_arguments)]
pub struct ImageFilter {
    pub album: Option<String>,
    pub media_type: Option<String>,
    pub time_from: Option<i64>,
    pub time_to: Option<i64>,
    pub has_location: Option<bool>,
    pub min_lat: Option<f64>,
    pub max_lat: Option<f64>,
    pub min_lon: Option<f64>,
    pub max_lon: Option<f64>,
    pub filename: Option<String>,
    pub has_faces: Option<bool>,
    pub min_faces: Option<usize>,
    pub person: Option<String>,
}

pub fn filter_images<'a>(
    files: &'a HashMap<i64, ImageFile>,
    f: &ImageFilter,
) -> Vec<&'a ImageFile> {
    let album_lc = f.album.as_ref().map(|s| s.to_lowercase());
    let media_lc = f.media_type.as_ref().map(|s| s.to_lowercase());
    let filename_lc = f.filename.as_ref().map(|s| s.to_lowercase());
    let person_lc = f.person.as_ref().map(|s| s.to_lowercase());

    let mut result: Vec<&ImageFile> = files
        .values()
        .filter(|file| !file.is_deleted)
        .filter(|file| {
            if let Some(a) = &album_lc {
                if !file.album_name.to_lowercase().contains(a) {
                    return false;
                }
            }
            if let Some(m) = &media_lc {
                if file.media_type() != m {
                    return false;
                }
            }
            if let Some(tf) = f.time_from {
                if file.creation_time.map_or(true, |c| c < tf) {
                    return false;
                }
            }
            if let Some(tt) = f.time_to {
                if file.creation_time.map_or(true, |c| c > tt) {
                    return false;
                }
            }
            let located = file.latitude.is_some() && file.longitude.is_some();
            if let Some(hl) = f.has_location {
                if located != hl {
                    return false;
                }
            }
            if let Some(v) = f.min_lat {
                if !located || file.latitude.unwrap() < v {
                    return false;
                }
            }
            if let Some(v) = f.max_lat {
                if !located || file.latitude.unwrap() > v {
                    return false;
                }
            }
            if let Some(v) = f.min_lon {
                if !located || file.longitude.unwrap() < v {
                    return false;
                }
            }
            if let Some(v) = f.max_lon {
                if !located || file.longitude.unwrap() > v {
                    return false;
                }
            }
            if let Some(fname) = &filename_lc {
                match &file.title {
                    Some(t) if t.to_lowercase().contains(fname) => {}
                    _ => return false,
                }
            }
            if let Some(hf) = f.has_faces {
                if !file.faces.is_empty() != hf {
                    return false;
                }
            }
            if let Some(mf) = f.min_faces {
                if file.faces.len() < mf {
                    return false;
                }
            }
            if let Some(p) = &person_lc {
                let matched = file.faces.iter().any(|fc| {
                    fc.person_name
                        .as_ref()
                        .map_or(false, |n| n.to_lowercase().contains(p))
                });
                if !matched {
                    return false;
                }
            }
            true
        })
        .collect();

    result.sort_by(|a, b| b.creation_time.unwrap_or(0).cmp(&a.creation_time.unwrap_or(0)));
    result
}
