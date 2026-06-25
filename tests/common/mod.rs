use lopdf::{dictionary, Document, Object, Stream};
use std::path::Path;

/// Ensure the sample fixture PDF exists. Creates it if missing.
pub fn ensure_sample_pdf() {
    let path = "tests/fixtures/sample.pdf";
    if Path::new(path).exists() {
        return;
    }
    std::fs::create_dir_all("tests/fixtures").unwrap();
    create_sample_pdf(path);
}

fn create_sample_pdf(path: &str) {
    let mut doc = Document::with_version("1.7");

    let font_id = doc.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });

    let resources_id = doc.add_object(dictionary! {
        "Font" => dictionary! {
            "F1" => Object::Reference(font_id),
        },
    });

    let content = b"BT /F1 24 Tf 100 700 Td (Hello pdfk!) Tj ET";
    let content_stream = Stream::new(
        dictionary! { "Length" => content.len() as i64 },
        content.to_vec(),
    );
    let content_id = doc.add_object(Object::Stream(content_stream));

    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Contents" => Object::Reference(content_id),
        "Resources" => Object::Reference(resources_id),
    });

    let pages_id = doc.add_object(dictionary! {
        "Type" => "Pages",
        "Kids" => vec![Object::Reference(page_id)],
        "Count" => 1,
    });

    if let Ok(page) = doc.get_object_mut(page_id) {
        if let Object::Dictionary(ref mut dict) = page {
            dict.set("Parent", Object::Reference(pages_id));
        }
    }

    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => Object::Reference(pages_id),
    });

    doc.trailer.set("Root", Object::Reference(catalog_id));
    doc.save(path).expect("Failed to save fixture PDF");
}

/// Ensure a fixture PDF with one image XObject and a tagged `/Figure` caption.
/// Returns its path.
pub fn ensure_image_pdf() -> &'static str {
    let path = "tests/fixtures/sample_image.pdf";
    if !Path::new(path).exists() {
        std::fs::create_dir_all("tests/fixtures").unwrap();
        create_image_pdf(path);
    }
    path
}

fn create_image_pdf(path: &str) {
    let mut doc = Document::with_version("1.7");

    let font_id = doc.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });

    let image_data = vec![0u8; 100 * 50 * 3];
    let image_stream = Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Image",
            "Width" => 100,
            "Height" => 50,
            "ColorSpace" => "DeviceRGB",
            "BitsPerComponent" => 8,
            "Length" => image_data.len() as i64,
        },
        image_data,
    );
    let image_id = doc.add_object(Object::Stream(image_stream));

    let resources_id = doc.add_object(dictionary! {
        "Font" => dictionary! { "F1" => Object::Reference(font_id) },
        "XObject" => dictionary! { "Im1" => Object::Reference(image_id) },
    });

    let content =
        b"BT /F1 24 Tf 100 700 Td (Picture below) Tj ET\nq 100 0 0 50 100 600 cm /Im1 Do Q";
    let content_id = doc.add_object(Object::Stream(Stream::new(
        dictionary! { "Length" => content.len() as i64 },
        content.to_vec(),
    )));

    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Contents" => Object::Reference(content_id),
        "Resources" => Object::Reference(resources_id),
    });

    let figure_id = doc.add_object(dictionary! {
        "Type" => "StructElem",
        "S" => "Figure",
        "Alt" => Object::string_literal("A test image caption"),
        "Pg" => Object::Reference(page_id),
    });
    let struct_root_id = doc.add_object(dictionary! {
        "Type" => "StructTreeRoot",
        "K" => Object::Reference(figure_id),
    });

    let pages_id = doc.add_object(dictionary! {
        "Type" => "Pages",
        "Kids" => vec![Object::Reference(page_id)],
        "Count" => 1,
    });

    if let Ok(Object::Dictionary(dict)) = doc.get_object_mut(page_id) {
        dict.set("Parent", Object::Reference(pages_id));
    }

    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => Object::Reference(pages_id),
        "StructTreeRoot" => Object::Reference(struct_root_id),
    });

    doc.trailer.set("Root", Object::Reference(catalog_id));
    doc.save(path).expect("Failed to save image fixture PDF");
}

/// Ensure a fixture PDF whose text starts with Markdown-special characters.
/// Returns its path.
pub fn ensure_markdown_pdf() -> &'static str {
    let path = "tests/fixtures/sample_markdown.pdf";
    if !Path::new(path).exists() {
        std::fs::create_dir_all("tests/fixtures").unwrap();
        create_markdown_pdf(path);
    }
    path
}

fn create_markdown_pdf(path: &str) {
    let mut doc = Document::with_version("1.7");

    let font_id = doc.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });

    let resources_id = doc.add_object(dictionary! {
        "Font" => dictionary! { "F1" => Object::Reference(font_id) },
    });

    let content = b"BT /F1 24 Tf 100 700 Td (# Heading line) Tj ET";
    let content_id = doc.add_object(Object::Stream(Stream::new(
        dictionary! { "Length" => content.len() as i64 },
        content.to_vec(),
    )));

    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Contents" => Object::Reference(content_id),
        "Resources" => Object::Reference(resources_id),
    });

    let pages_id = doc.add_object(dictionary! {
        "Type" => "Pages",
        "Kids" => vec![Object::Reference(page_id)],
        "Count" => 1,
    });

    if let Ok(Object::Dictionary(dict)) = doc.get_object_mut(page_id) {
        dict.set("Parent", Object::Reference(pages_id));
    }

    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => Object::Reference(pages_id),
    });

    doc.trailer.set("Root", Object::Reference(catalog_id));
    doc.save(path).expect("Failed to save markdown fixture PDF");
}
