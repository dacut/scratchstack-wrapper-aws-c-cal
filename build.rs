use {
    bindgen::builder,
    std::{env::var, fs::{create_dir_all, copy, read_dir}, path::PathBuf},
};

fn main() {
    let root = PathBuf::from(var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let out_dir = PathBuf::from(var("OUT_DIR").expect("OUT_DIR not set"));
    let aws_c_common_include_dir =
        PathBuf::from(var("DEP_AWS_C_COMMON_INCLUDE").expect("DEP_AWS_C_COMMON_INCLUDE not set"));
    let aws_c_common_include_dir_str = aws_c_common_include_dir.to_string_lossy();
    let aws_lc_include_dir =
        PathBuf::from(var("DEP_AWS_LC_INCLUDE").expect("DEP_AWS_LC_INCLUDE not set"));
    let aws_lc_include_dir_str = aws_lc_include_dir.to_string_lossy();

    let src_include_dir = root.join("include");
    let dst_include_dir = out_dir.join("include");
    let src_lib_include_dir = src_include_dir.join("aws").join("cal");
    let dst_lib_include_dir = dst_include_dir.join("aws").join("cal");
    let src_include_dir_str = src_include_dir.to_string_lossy();
    let dst_include_dir_str = dst_include_dir.to_string_lossy();
    let src_lib_include_dir_str = src_lib_include_dir.to_string_lossy();
    let dst_lib_include_dir_str = dst_lib_include_dir.to_string_lossy();

    println!("cargo:include={dst_include_dir_str}");
    println!("cargo:rerun-if-changed=include");
    println!("cargo:rerun-if-env-changed=AWS_CRT_PREFIX");

    if let Ok(aws_crt_prefix) = var("AWS_CRT_PREFIX") {
        println!("cargo:rustc-link-search={aws_crt_prefix}/lib");
    }

    println!("cargo:rustc-link-lib=aws-c-cal");

    // Copy include files over
    create_dir_all(&dst_lib_include_dir).unwrap_or_else(|e| panic!("Unable to create directory {dst_lib_include_dir_str}: {e}"));

    let mut builder = builder()
        .clang_arg(format!("-I{src_include_dir_str}"))
        .clang_arg(format!("-I{aws_c_common_include_dir_str}"))
        .clang_arg(format!("-I{aws_lc_include_dir_str}"))
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .derive_eq(true);

    let mut n_includes = 0;

    for entry in read_dir(&src_lib_include_dir).unwrap_or_else(|e| panic!("Unable to list header files in {src_lib_include_dir_str}: {e}")) {
        let entry = entry.unwrap_or_else(|e| panic!("Unable to read directory entry in {src_lib_include_dir_str}: {e}"));
        let file_name_string = entry.file_name();
        let src_path = src_lib_include_dir.join(&file_name_string);
        let src_path_str = src_path.to_string_lossy();
        let dst_path = dst_lib_include_dir.join(&file_name_string);

        if entry.file_type().unwrap_or_else(|e| panic!("Unable to read file type of {src_path_str}: {e}")).is_file() {
            // Only include header files ending with .h; ignore .inl.
        let file_name_utf8 = file_name_string.to_str().expect("Unable to convert file name to UTF-8");
            if file_name_utf8.ends_with(".h") {
                builder = builder.header(src_path_str.to_string());
                n_includes += 1;
            }

            // Copy all files to the output directory.
            copy(&src_path, &dst_path).unwrap_or_else(|e| panic!("Failed to copy from {src_path_str} to {dst_path_str}: {e}", dst_path_str = dst_path.to_string_lossy()));
        }
    }

    if n_includes == 0 {
        panic!("No header files found in include/aws/cal");
    }

    builder = builder.allowlist_function("aws_.*").allowlist_type("aws_.*").allowlist_var("aws_.*");

    let bindings_filename = out_dir.join("bindings.rs");
    let bindings = builder.generate().expect("Unable to generate bindings");
    bindings.write_to_file(&bindings_filename).unwrap_or_else(|e| panic!("Failed to write bindings to {bindings_filename_str}: {e}", bindings_filename_str = bindings_filename.to_string_lossy()));

    if cfg!(any(target_os = "ios", target_os = "macos")) {
        println!("cargo:rustc-link-arg=-framework");
        println!("cargo:rustc-link-arg=CoreFoundation");
    }
}
