from io import BytesIO

from PIL import Image, ImageDraw

from app.services.ocr import extract_text_from_image


def test_local_ocr_extracts_text_without_external_provider() -> None:
    image = Image.new("RGB", (900, 180), "white")
    ImageDraw.Draw(image).text((24, 56), "Oferta exclusiva: 70% de descuento", fill="black")
    buffer = BytesIO()
    image.save(buffer, format="PNG")

    result = extract_text_from_image(buffer.getvalue())

    assert "Oferta exclusiva" in result
    assert "descuento" in result
