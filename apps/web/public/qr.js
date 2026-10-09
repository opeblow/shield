const maximumImageBytes = 5 * 1024 * 1024;
const maximumPayloadLength = 20_000;
const acceptedImageTypes = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/avif', 'image/bmp']);

export async function decodeQrFile(file, { Detector = globalThis.BarcodeDetector, bitmapFactory = globalThis.createImageBitmap } = {}) {
  if (!file || typeof file.size !== 'number' || !acceptedImageTypes.has(file.type)) {
    throw new Error('Choose a JPEG, PNG, WebP, AVIF or BMP image containing a QR code.');
  }
  if (file.size === 0 || file.size > maximumImageBytes) throw new Error('Choose an image smaller than 5 MB.');
  if (!Detector || !bitmapFactory) throw new Error('QR image reading is not supported in this browser. You can paste the link or message instead.');

  const bitmap = await bitmapFactory(file, { resizeWidth: 2048, resizeQuality: 'low' });
  try {
    const detector = new Detector({ formats: ['qr_code'] });
    const codes = await detector.detect(bitmap);
    const payload = codes.find((code) => typeof code.rawValue === 'string' && code.rawValue.trim())?.rawValue.trim();
    if (!payload) throw new Error('No readable QR code was found in that image.');
    if (payload.length > maximumPayloadLength) throw new Error('The QR content is too long to scan safely.');
    return payload;
  } finally {
    bitmap.close?.();
  }
}
