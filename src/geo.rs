use crate::model::GeoInfo;
use maxminddb::geoip2;
use std::net::IpAddr;
use std::path::Path;

pub struct Geo {
    reader: parking_lot::RwLock<Option<maxminddb::Reader<Vec<u8>>>>,
}

impl Geo {
    /// Opens the database when present; otherwise starts empty and `load` can fill it in later.
    pub fn open(path: &Path) -> Self {
        let g = Self { reader: parking_lot::RwLock::new(None) };
        if path.exists() {
            g.load(path);
        } else {
            tracing::warn!("GeoIP database not present yet; destinations have no location until it is downloaded");
        }
        g
    }

    pub fn load(&self, path: &Path) {
        match maxminddb::Reader::open_readfile(path) {
            Ok(r) => {
                tracing::info!("GeoIP database loaded from {}", path.display());
                *self.reader.write() = Some(r);
            }
            Err(e) => tracing::warn!("GeoIP database could not be opened ({e})"),
        }
    }

    pub fn available(&self) -> bool {
        self.reader.read().is_some()
    }

    pub fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let guard = self.reader.read();
        let Some(r) = guard.as_ref() else { return GeoInfo::default() };
        let Ok(result) = r.lookup(ip) else { return GeoInfo::default() };
        let Ok(Some(city)) = result.decode::<geoip2::City>() else { return GeoInfo::default() };
        let country = city.country.iso_code.map(|s| s.to_string());
        let country_name = city.country.names.english.map(|s| s.to_string());
        let city_name = city.city.names.english.map(|s| s.to_string());
        let (lat, lon) = (city.location.latitude, city.location.longitude);
        GeoInfo { country, country_name, city: city_name, lat, lon }
    }
}

/// Download the DB-IP lite database when missing (gzip, about 120 MB).
pub async fn ensure_database(path: &Path, url_template: &str) -> anyhow::Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let now = chrono::Utc::now();
    let mut candidates = vec![];
    for back in 0..2 {
        let d = now - chrono::Months::new(back);
        candidates.push(
            url_template
                .replace("{YYYY}", &d.format("%Y").to_string())
                .replace("{MM}", &d.format("%m").to_string()),
        );
    }
    let client = reqwest::Client::builder().user_agent("NetMonitor/0.1").build()?;
    for url in candidates {
        tracing::info!("downloading GeoIP database from {url}");
        let resp = match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::warn!("GeoIP download {url} returned {}", r.status());
                continue;
            }
            Err(e) => {
                tracing::warn!("GeoIP download failed: {e}");
                continue;
            }
        };
        let bytes = resp.bytes().await?;
        let gz_path = path.with_extension("mmdb.gz");
        std::fs::write(&gz_path, &bytes)?;
        let f = std::fs::File::open(&gz_path)?;
        let mut dec = flate2::read::GzDecoder::new(f);
        let mut out = std::fs::File::create(path)?;
        std::io::copy(&mut dec, &mut out)?;
        let _ = std::fs::remove_file(&gz_path);
        tracing::info!("GeoIP database saved to {}", path.display());
        return Ok(());
    }
    anyhow::bail!("could not download GeoIP database")
}
