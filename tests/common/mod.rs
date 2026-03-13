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
