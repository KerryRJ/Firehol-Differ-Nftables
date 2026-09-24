use serde::{Serialize, Deserialize};
use std::path::Path;
use tokio::fs;

#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct Etags {
    pub(crate) l1: Option<String>,
    pub(crate) l2: Option<String>,
}

impl Etags {
    pub(crate) async fn load(data_dir: &Path) -> Result<Self, anyhow::Error> {
        let path = data_dir.join("etags.json");
        if !fs::try_exists(&path).await? {
            Ok(Self::default())
        } else {
            let data = fs::read_to_string(path).await?;
            let etags = serde_json::from_str(&data)?;
            Ok(etags)
        }
    }
    pub(crate) async fn save(&self, data_dir: &Path) -> Result<(), anyhow::Error> {
        let data = serde_json::to_string_pretty(self)?;
        fs::write(data_dir.join("etags.json"), data).await?;
        Ok(())
    }
}
