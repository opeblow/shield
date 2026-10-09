import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeQrFile } from '../apps/web/public/qr.js';

function qrHarness(codes) {
  let closed = false;
  class Detector {
    constructor(options) { assert.deepEqual(options.formats, ['qr_code']); }
    async detect(bitmap) { assert.equal(bitmap.marker, 'decoded-locally'); return codes; }
  }
  return {
    options: { Detector, bitmapFactory: async (_file, settings) => {
      assert.equal(settings.resizeWidth, 2048);
      assert.equal(settings.resizeQuality, 'low');
      return { marker: 'decoded-locally', close() { closed = true; } };
    } },
    wasClosed: () => closed
  };
}

test('QR image decoding returns payload without uploading and closes the bitmap', async () => {
  const file = new Blob(['image bytes'], { type: 'image/png' });
  const harness = qrHarness([{ rawValue: ' https://example.ng/pay ' }]);
  assert.equal(await decodeQrFile(file, harness.options), 'https://example.ng/pay');
  assert.equal(harness.wasClosed(), true);
});

test('QR decoder rejects unsupported content, oversized images and empty QR results', async () => {
  await assert.rejects(decodeQrFile(new Blob(['svg'], { type: 'image/svg+xml' }), qrHarness([]).options), /JPEG, PNG/);
  await assert.rejects(decodeQrFile(new Blob(['text'], { type: 'text/plain' }), qrHarness([]).options), /JPEG, PNG/);
  await assert.rejects(decodeQrFile({ size: 5 * 1024 * 1024 + 1, type: 'image/png' }, qrHarness([]).options), /smaller than 5 MB/);
  const empty = qrHarness([]);
  await assert.rejects(decodeQrFile(new Blob(['image'], { type: 'image/jpeg' }), empty.options), /No readable QR/);
  assert.equal(empty.wasClosed(), true);
  await assert.rejects(decodeQrFile(new Blob(['image'], { type: 'image/png' }), { Detector: undefined, bitmapFactory: undefined }), /not supported/);
});
