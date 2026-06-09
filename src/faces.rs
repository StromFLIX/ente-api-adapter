//! Detected-face (ML) and named-person ("cgroup") integration.
//!
//! Ente stores per-file ML inference (including detected faces) as a separate
//! "mldata" dataset, and named people as encrypted "cgroup" user entities.
//! Both payloads are gzipped *then* encrypted:
//!
//! - mldata is encrypted with the per-file key (same key that decrypts the
//!   blob/metadata) and fetched via `POST /files/data/fetch`.
//! - cgroup entities are encrypted with a per-type entity key (itself encrypted
//!   with the account master key) and fetched via `/user-entity/*`.
//!
//! This module fetches, decrypts and joins them so the adapter can expose real
//! face boxes annotated with the person each face belongs to.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use crate::client::{EnteApiError, MuseumClient};
use crate::crypto::{decrypt_chacha, gunzip, secretbox_open};
use crate::files::ImageFile;

const ENTITY_DIFF_LIMIT: i64 = 500;

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

/// The fileID is the prefix of a faceID (`"{fileID}_{hash}"`).
fn file_id_from_face_id(face_id: &str) -> Option<i64> {
    face_id.split('_').next()?.parse().ok()
}

/// A single detected face within an image.
#[derive(Clone)]
pub struct DetectedFace {
    pub face_id: String,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub score: f64,
    pub blur: f64,
    pub person_id: Option<String>,
    pub person_name: Option<String>,
}

impl DetectedFace {
    pub fn as_json(&self) -> Value {
        json!({
            "faceId": self.face_id,
            "box": {
                "x": self.x,
                "y": self.y,
                "width": self.width,
                "height": self.height,
            },
            "score": self.score,
            "blur": self.blur,
            "personId": self.person_id,
            "personName": self.person_name,
        })
    }
}

/// Face data attached to one file: the detected faces plus the dimensions of
/// the image the face boxes are relative to.
#[derive(Clone, Default)]
pub struct FileFaces {
    pub image_width: Option<i64>,
    pub image_height: Option<i64>,
    pub faces: Vec<DetectedFace>,
}

/// A named person ("cgroup").
#[derive(Clone)]
pub struct Person {
    pub id: String,
    pub name: String,
}

/// Lookup tables joining faces/files back to named people.
#[derive(Default)]
pub struct PeopleIndex {
    /// All named, non-hidden people, keyed by entity id.
    pub people: HashMap<String, Person>,
    /// faceID -> person id.
    pub face_to_person: HashMap<String, String>,
    /// person id -> set of fileIDs assigned to them (via faces or manually).
    pub person_file_ids: HashMap<String, HashSet<i64>>,
}

impl PeopleIndex {
    /// Resolve the (id, name) of the person a face belongs to, if any.
    fn person_for_face(&self, face_id: &str) -> (Option<String>, Option<String>) {
        match self.face_to_person.get(face_id) {
            Some(pid) => {
                let name = self.people.get(pid).map(|p| p.name.clone());
                (Some(pid.clone()), name)
            }
            None => (None, None),
        }
    }

    /// Per-person summaries `(id, name, image_count)`, counting only images that
    /// are still present (and not deleted) in `library`. Sorted by count desc.
    pub fn summaries(
        &self,
        library: &HashMap<i64, ImageFile>,
    ) -> Vec<(String, String, usize)> {
        let mut out: Vec<(String, String, usize)> = self
            .people
            .values()
            .map(|p| {
                let count = self
                    .person_file_ids
                    .get(&p.id)
                    .map(|set| {
                        set.iter()
                            .filter(|fid| {
                                library.get(fid).map_or(false, |f| !f.is_deleted)
                            })
                            .count()
                    })
                    .unwrap_or(0);
                (p.id.clone(), p.name.clone(), count)
            })
            .collect();
        out.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.1.cmp(&b.1)));
        out
    }
}

/// Fetch and decrypt all named people ("cgroup" user entities) from museum.
///
/// Returns an empty index (not an error) if the account has no people yet
/// (museum answers 404 to the entity-key request in that case).
pub async fn fetch_people(
    client: &MuseumClient,
    master_key: &[u8],
) -> Result<PeopleIndex, EnteApiError> {
    // 1. Fetch the cgroup entity key, itself encrypted with the master key.
    let key_resp = match client
        .get("/user-entity/key", &[("type", "cgroup".to_string())])
        .await
    {
        Ok(v) => v,
        Err(e) if e.status_code() == 404 => return Ok(PeopleIndex::default()),
        Err(e) => return Err(e),
    };

    let enc_key = key_resp
        .get("encryptedKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| EnteApiError::Decode("entity key missing encryptedKey".into()))?;
    let header = key_resp
        .get("header")
        .and_then(|v| v.as_str())
        .ok_or_else(|| EnteApiError::Decode("entity key missing header".into()))?;
    let entity_key = secretbox_open(enc_key, header, master_key)
        .map_err(|e| EnteApiError::Decode(e.to_string()))?;

    // 2. Page through the entity diff, decrypting each cgroup.
    let mut index = PeopleIndex::default();
    let mut since = 0i64;
    loop {
        let page = client
            .get(
                "/user-entity/entity/diff",
                &[
                    ("type", "cgroup".to_string()),
                    ("sinceTime", since.to_string()),
                    ("limit", ENTITY_DIFF_LIMIT.to_string()),
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
        let page_len = diff.len() as i64;

        for entry in &diff {
            if let Some(ut) = entry.get("updatedAt").and_then(as_i64) {
                since = since.max(ut);
            }
            let id = entry
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if id.is_empty() {
                continue;
            }
            let is_deleted = entry
                .get("isDeleted")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if is_deleted {
                index.people.remove(&id);
                index.person_file_ids.remove(&id);
                index.face_to_person.retain(|_, pid| pid != &id);
                continue;
            }

            let (enc_data, hdr) = match (
                entry.get("encryptedData").and_then(|v| v.as_str()),
                entry.get("header").and_then(|v| v.as_str()),
            ) {
                (Some(d), Some(h)) => (d, h),
                _ => continue,
            };
            let plain = match decrypt_chacha(enc_data, &entity_key, hdr) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let json_bytes = match gunzip(&plain) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let data: Value = match serde_json::from_slice(&json_bytes) {
                Ok(v) => v,
                Err(_) => continue,
            };
            ingest_cgroup(&mut index, &id, &data);
        }

        if page_len < ENTITY_DIFF_LIMIT {
            break;
        }
    }
    Ok(index)
}

/// Parse a single decrypted cgroup entity into the people index. Only named,
/// non-hidden groups (i.e. actual "people") are kept.
fn ingest_cgroup(index: &mut PeopleIndex, id: &str, data: &Value) {
    let is_hidden = data.get("isHidden").and_then(Value::as_bool).unwrap_or(false);
    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();
    if is_hidden || name.is_empty() {
        return;
    }

    let mut file_ids: HashSet<i64> = HashSet::new();
    let mut face_ids: Vec<String> = Vec::new();

    if let Some(assigned) = data.get("assigned").and_then(Value::as_array) {
        for cluster in assigned {
            if let Some(faces) = cluster.get("faces").and_then(Value::as_array) {
                for f in faces {
                    if let Some(face_id) = f.as_str() {
                        if let Some(fid) = file_id_from_face_id(face_id) {
                            file_ids.insert(fid);
                        }
                        face_ids.push(face_id.to_string());
                    }
                }
            }
        }
    }
    if let Some(manual) = data.get("manuallyAssigned").and_then(Value::as_array) {
        for m in manual {
            if let Some(fid) = as_i64(m) {
                file_ids.insert(fid);
            }
        }
    }

    index
        .people
        .insert(id.to_string(), Person { id: id.to_string(), name });
    for face_id in face_ids {
        index.face_to_person.insert(face_id, id.to_string());
    }
    index.person_file_ids.insert(id.to_string(), file_ids);
}

/// Fetch and decrypt detected faces for all (non-deleted) files in `files`,
/// joining each face to its person via `people`.
pub async fn fetch_faces(
    client: &MuseumClient,
    files: &HashMap<i64, ImageFile>,
    people: &PeopleIndex,
    batch_size: usize,
) -> Result<HashMap<i64, FileFaces>, EnteApiError> {
    let mut result: HashMap<i64, FileFaces> = HashMap::new();
    let ids: Vec<i64> = files
        .values()
        .filter(|f| !f.is_deleted)
        .map(|f| f.id)
        .collect();
    let batch = batch_size.clamp(1, 1000);

    for chunk in ids.chunks(batch) {
        let body = json!({ "type": "mldata", "fileIDs": chunk });
        let resp = match client.post("/files/data/fetch", &body).await {
            Ok(v) => v,
            // Best-effort: an upstream that doesn't support mldata (or a
            // transient error) shouldn't break image listing.
            Err(e) => {
                tracing::debug!("mldata fetch failed for a batch: {e}");
                continue;
            }
        };
        let data = resp
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for entry in &data {
            let fid = match entry.get("fileID").and_then(as_i64) {
                Some(x) => x,
                None => continue,
            };
            let file = match files.get(&fid) {
                Some(f) => f,
                None => continue,
            };
            let (enc, hdr) = match (
                entry.get("encryptedData").and_then(|v| v.as_str()),
                entry.get("decryptionHeader").and_then(|v| v.as_str()),
            ) {
                (Some(a), Some(b)) => (a, b),
                _ => continue,
            };
            let plain = match decrypt_chacha(enc, &file.key, hdr) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let json_bytes = match gunzip(&plain) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let ml: Value = match serde_json::from_slice(&json_bytes) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(ff) = parse_face_index(&ml, people) {
                result.insert(fid, ff);
            }
        }
    }
    Ok(result)
}

/// Extract the `face` sub-object of a decrypted mldata payload into `FileFaces`.
fn parse_face_index(ml: &Value, people: &PeopleIndex) -> Option<FileFaces> {
    let face = ml.get("face")?;
    let image_width = face.get("width").and_then(as_i64);
    let image_height = face.get("height").and_then(as_i64);

    let mut faces = Vec::new();
    if let Some(arr) = face.get("faces").and_then(Value::as_array) {
        for f in arr {
            let face_id = f
                .get("faceID")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let bx = f.get("detection").and_then(|d| d.get("box"));
            let getf = |k: &str| bx.and_then(|b| b.get(k)).and_then(as_f64).unwrap_or(0.0);
            let (person_id, person_name) = people.person_for_face(&face_id);
            faces.push(DetectedFace {
                face_id,
                x: getf("x"),
                y: getf("y"),
                width: getf("width"),
                height: getf("height"),
                score: f.get("score").and_then(as_f64).unwrap_or(0.0),
                blur: f.get("blur").and_then(as_f64).unwrap_or(0.0),
                person_id,
                person_name,
            });
        }
    }

    Some(FileFaces {
        image_width,
        image_height,
        faces,
    })
}

/// Attach fetched face data onto the matching files in the library.
pub fn attach_faces(files: &mut HashMap<i64, ImageFile>, faces: HashMap<i64, FileFaces>) {
    for (fid, ff) in faces {
        if let Some(file) = files.get_mut(&fid) {
            file.face_image_width = ff.image_width;
            file.face_image_height = ff.image_height;
            file.faces = ff.faces;
        }
    }
}
