use std::path::Path;

use crate::plugins::artifact_plugin::ArtifactPlugin;
use crate::plugins::mft::MftPlugin;
use crate::plugins::secure::SecurePlugin;
use crate::plugins::usn::UsnPlugin;

pub struct PluginRegistry {
    plugins: Vec<Box<dyn ArtifactPlugin + Send + Sync>>,
}

impl PluginRegistry {
    pub fn with_builtins() -> PluginRegistry {
        let plugins: Vec<Box<dyn ArtifactPlugin + Send + Sync>> =
            vec![Box::new(MftPlugin), Box::new(UsnPlugin), Box::new(SecurePlugin)];
        PluginRegistry { plugins }
    }

    pub fn ids(&self) -> Vec<&'static str> {
        self.plugins.iter().map(|p| p.id()).collect()
    }

    pub fn by_id(&self, id: &str) -> Option<&(dyn ArtifactPlugin + Send + Sync)> {
        self.plugins.iter().find(|p| p.id() == id).map(|b| b.as_ref())
    }

    pub fn identify(&self, header: &[u8]) -> Option<&(dyn ArtifactPlugin + Send + Sync)> {
        self.plugins.iter().find(|p| p.identify(header)).map(|b| b.as_ref())
    }

    pub fn identify_path(&self, path: &Path) -> Option<&'static str> {
        let header = read_header(path, 512);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        self.plugins
            .iter()
            .find(|p| p.identify(&header) || p.identify_name(name))
            .map(|b| b.id())
    }
}

fn read_header(path: &Path, len: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buf = vec![0u8; len];
    if let Ok(mut f) = std::fs::File::open(path) {
        let read = f.read(&mut buf).unwrap_or(0);
        buf.truncate(read);
    } else {
        buf.clear();
    }
    buf
}
