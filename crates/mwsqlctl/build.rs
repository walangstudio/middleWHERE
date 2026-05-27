// Embeds Windows version-info and an application manifest into the binary.
// Native PE files with real metadata and an asInvoker manifest avoid the
// "unsigned, zero-metadata executable" heuristic that flags AV false positives.
// Only runs when building on/for Windows; a no-op everywhere else.

#[cfg(windows)]
const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
      <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"/>
    </application>
  </compatibility>
</assembly>"#;

#[cfg(windows)]
fn main() {
    let mut res = winresource::WindowsResource::new();
    res.set("CompanyName", "walang.studio");
    res.set("ProductName", "middleWHERE");
    res.set("FileDescription", "middleWHERE admin CLI");
    res.set("LegalCopyright", "(c) 2026 scr1p7k177y. MIT License.");
    res.set("OriginalFilename", "mwsqlctl.exe");
    res.set_manifest(MANIFEST);
    if let Err(e) = res.compile() {
        println!("cargo:warning=winresource: failed to embed metadata: {e}");
    }
}

#[cfg(not(windows))]
fn main() {}
