// Same calls as `bun build --compile --target=bun-darwin-x64`
// (src/standalone_graph/StandaloneModuleGraph.rs: MachoFile::init + write_section).
use bun_exe_format::macho::MachoFile;

#[test]
fn compile_for_macos() {
    let template = std::fs::read("/templates/bun-darwin-x64/bun").unwrap();
    let module_graph = vec![0u8; 1 << 20];
    let mut exe = MachoFile::init(&template, module_graph.len()).unwrap();
    exe.write_section(&module_graph).unwrap();
}
