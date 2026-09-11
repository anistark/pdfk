use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::cli::ReadFormat;
use crate::pdf::reader::{self, PageImage};
use crate::utils::batch::{self, BatchSummary};
use crate::utils::editor;
use crate::utils::{
    display_path, is_quiet, print_error, print_success, resolve_password, write_stdout,
};
use log::warn;
use lopdf::Document;

#[derive(Serialize, Clone)]
struct ReadOutput {
    file: String,
    encrypted: bool,
    page_count: usize,
    pages: Vec<PageOutput>,
}

/// How (and whether) to hand the rendered output to an editor or pager.
pub struct OpenOptions {
    pub enabled: bool,
    pub editor: Option<String>,
    pub allow_temp: bool,
}

/// Everything `emit` needs to place the rendered output somewhere.
struct EmitOptions<'a> {
    format: ReadFormat,
    no_headers: bool,
    output: Option<&'a Path>,
    /// Resolved editor command line, when `--open`/`--editor` was given.
    open: Option<&'a str>,
    allow_temp: bool,
    is_batch: bool,
}

#[derive(Serialize, Clone)]
struct PageOutput {
    page: u32,
    text: String,
    images: Vec<PageImage>,
    warnings: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
pub fn execute(
    files: Vec<PathBuf>,
    format: ReadFormat,
    output: Option<PathBuf>,
    no_headers: bool,
    no_images: bool,
    password: Option<String>,
    password_stdin: bool,
    password_env: Option<String>,
    password_cmd: Option<String>,
    recursive: bool,
    open: OpenOptions,
) -> Result<()> {
    if open.allow_temp && !open.enabled {
        bail!("--allow-temp only applies with --open/--editor");
    }
    if open.enabled && is_quiet() {
        bail!("--open cannot be combined with --quiet");
    }

    let resolved = batch::resolve_files(&files, recursive)?;

    if output.is_some() && resolved.len() > 1 {
        bail!("--output can only be used with a single input file");
    }
    if open.enabled && resolved.len() > 1 {
        bail!("--open can only be used with a single input file");
    }

    // Resolve before doing any work, so a missing editor fails fast.
    let editor_cmd = if open.enabled {
        Some(editor::resolve_editor(open.editor)?)
    } else {
        None
    };

    let is_batch = resolved.len() > 1;
    let pb = batch::create_progress_bar(resolved.len());
    let mut summary = BatchSummary::default();
    let mut json_outputs: Vec<ReadOutput> = Vec::new();
    let mut password_cache: Option<String> = None;

    for file in &resolved {
        if let Some(ref pb) = pb {
            pb.set_message(display_path(file));
        }

        let result = (|| -> Result<()> {
            if !file.exists() {
                bail!("File not found: {}", display_path(file));
            }
            let probe = reader::load_pdf(file)?;
            let encrypted = reader::is_encrypted(&probe);
            let doc = if encrypted {
                let pass = obtain_password(
                    &mut password_cache,
                    &password,
                    password_stdin,
                    &password_env,
                    &password_cmd,
                )?;
                reader::load_pdf_decrypted(file, &pass)?
            } else {
                probe
            };

            let pages = extract_pages(&doc, no_images);
            let out = ReadOutput {
                file: display_path(file),
                encrypted,
                page_count: pages.len(),
                pages,
            };
            emit(
                &out,
                &EmitOptions {
                    format,
                    no_headers,
                    output: output.as_deref(),
                    open: editor_cmd.as_deref(),
                    allow_temp: open.allow_temp,
                    is_batch,
                },
                &mut json_outputs,
            )
        })();

        match result {
            Ok(()) => summary.succeeded += 1,
            Err(e) => {
                print_error(&format!("{}: {}", display_path(file), e));
                summary.failed += 1;
            }
        }

        if let Some(ref pb) = pb {
            pb.inc(1);
        }
    }

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    if format == ReadFormat::Json && is_batch {
        write_stdout(&serde_json::to_string_pretty(&json_outputs)?);
    }

    if is_batch {
        summary.print();
    }

    if summary.has_failures() {
        bail!("{} file(s) failed", summary.failed);
    }

    Ok(())
}

fn obtain_password(
    cache: &mut Option<String>,
    password: &Option<String>,
    password_stdin: bool,
    password_env: &Option<String>,
    password_cmd: &Option<String>,
) -> Result<String> {
    if let Some(p) = cache {
        return Ok(p.clone());
    }
    let p = resolve_password(
        password.clone(),
        password_stdin,
        password_env.clone(),
        password_cmd.clone(),
    )?;
    *cache = Some(p.clone());
    Ok(p)
}

fn extract_pages(doc: &Document, no_images: bool) -> Vec<PageOutput> {
    let captions = if no_images {
        Default::default()
    } else {
        reader::collect_figure_captions(doc)
    };

    let pages = doc.get_pages();
    let mut out = Vec::with_capacity(pages.len());

    for (num, id) in pages {
        let mut text = String::new();
        let mut warnings = Vec::new();
        for chunk in doc.extract_text_chunks(&[num]) {
            match chunk {
                Ok(s) => text.push_str(&s),
                Err(e) => warnings.push(e.to_string()),
            }
        }

        let mut images = if no_images {
            Vec::new()
        } else {
            reader::list_page_images(doc, id)
        };
        if let Some(caps) = captions.get(&id) {
            for (i, img) in images.iter_mut().enumerate() {
                img.caption = caps.get(i).cloned();
            }
        }

        for w in &warnings {
            warn!("page {num}: {w}");
        }

        out.push(PageOutput {
            page: num,
            text,
            images,
            warnings,
        });
    }

    if out.is_empty() {
        warn!("no extractable pages found");
    }

    out
}

fn emit(out: &ReadOutput, opts: &EmitOptions, json_outputs: &mut Vec<ReadOutput>) -> Result<()> {
    match opts.format {
        ReadFormat::Json => {
            if opts.is_batch {
                json_outputs.push(out.clone());
            } else {
                write_payload(&serde_json::to_string_pretty(out)?, opts, out.encrypted)?;
            }
        }
        ReadFormat::Md | ReadFormat::Text => {
            let rendered = if opts.format == ReadFormat::Md {
                render_markdown(out, opts.no_headers)
            } else {
                render_text(out, opts.no_headers)
            };
            if opts.output.is_none() && opts.open.is_none() && opts.is_batch {
                write_stdout("");
            }
            write_payload(&rendered, opts, out.encrypted)?;
        }
    }
    Ok(())
}

fn write_payload(content: &str, opts: &EmitOptions, encrypted: bool) -> Result<()> {
    if let Some(cmd) = opts.open {
        return editor::open_with(
            cmd,
            content,
            opts.format.extension(),
            opts.allow_temp,
            encrypted,
        );
    }
    match opts.output {
        Some(path) => {
            std::fs::write(path, content)
                .with_context(|| format!("Failed to write {}", path.display()))?;
            print_success(&format!("Wrote {}", display_path(path)));
        }
        None => write_stdout(content),
    }
    Ok(())
}

fn render_markdown(out: &ReadOutput, no_headers: bool) -> String {
    let mut blocks: Vec<String> = Vec::new();

    if !no_headers {
        blocks.push(format!("# {}", out.file));
    }
    if out.pages.is_empty() {
        blocks.push("> ⚠️ no extractable pages found".to_string());
    }

    for page in &out.pages {
        let mut b = String::new();
        if !no_headers {
            b.push_str(&format!("## Page {}\n\n", page.page));
        }
        b.push_str(&escape_md(page.text.trim_end_matches('\n')));
        for img in &page.images {
            b.push_str(&format!("\n\n{}", md_image(img)));
        }
        for w in &page.warnings {
            b.push_str(&format!("\n\n> ⚠️ page {}: {}", page.page, w));
        }
        blocks.push(b.trim().to_string());
    }

    blocks.retain(|b| !b.is_empty());
    blocks.join("\n\n")
}

fn render_text(out: &ReadOutput, no_headers: bool) -> String {
    let mut blocks: Vec<String> = Vec::new();

    if out.pages.is_empty() {
        blocks.push("[!] no extractable pages found".to_string());
    }

    for page in &out.pages {
        let mut b = String::new();
        if !no_headers {
            b.push_str(&format!("--- Page {} ---\n", page.page));
        }
        b.push_str(page.text.trim_end_matches('\n'));
        for img in &page.images {
            b.push_str(&format!("\n{}", text_image(img)));
        }
        for w in &page.warnings {
            b.push_str(&format!("\n[!] page {}: {}", page.page, w));
        }
        blocks.push(b.trim_end().to_string());
    }

    blocks.retain(|b| !b.is_empty());
    blocks.join("\n\n")
}

fn md_image(img: &PageImage) -> String {
    let alt = img.caption.clone().unwrap_or_else(|| img.name.clone());
    let dims = match (img.width, img.height) {
        (Some(w), Some(h)) => format!(" <!-- {w}×{h} -->"),
        _ => String::new(),
    };
    format!("![{}](#{}){}", escape_alt(&alt), anchorize(&img.name), dims)
}

fn text_image(img: &PageImage) -> String {
    let mut s = format!("[image] {}", img.name);
    if let (Some(w), Some(h)) = (img.width, img.height) {
        s.push_str(&format!(" — {w}×{h}"));
    }
    if let Some(c) = &img.caption {
        s.push_str(&format!(" — caption: \"{}\"", c.replace('\n', " ")));
    }
    s
}

fn escape_md(text: &str) -> String {
    text.lines()
        .map(escape_md_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn escape_md_line(line: &str) -> String {
    let trimmed = line.trim_start();
    let indent = &line[..line.len() - trimmed.len()];
    let body = escape_leading_marker(trimmed).replace('`', "\\`");
    format!("{indent}{body}")
}

fn escape_leading_marker(s: &str) -> String {
    let Some(first) = s.chars().next() else {
        return String::new();
    };
    if matches!(first, '#' | '>' | '-' | '+' | '*') {
        return format!("\\{s}");
    }
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if !digits.is_empty() {
        let rest = &s[digits.len()..];
        if rest.starts_with('.') || rest.starts_with(')') {
            return format!("{digits}\\{rest}");
        }
    }
    s.to_string()
}

fn escape_alt(s: &str) -> String {
    s.replace('\n', " ").replace(']', "\\]")
}

fn anchorize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}
