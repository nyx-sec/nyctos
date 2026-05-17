// rust-embed bundle of the compiled frontend. The `dist/` folder is the
// vite build output; populated by a later frontend phase.

use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "dist/"]
pub struct UiAssets;
