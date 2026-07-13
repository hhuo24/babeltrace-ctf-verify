'use strict';

/*
 * CTF (Common Trace Format) 1.8.x metadata validator web app.
 *
 * Users upload a CTF trace (its `metadata` file, optionally with stream files,
 * or a .zip containing them). The server drops the files into a temporary trace
 * directory and runs babeltrace2 against it, then returns the exact stdout /
 * stderr / exit code so the user sees the real success or error message.
 *
 * The path to the babeltrace2 binary can be overridden with the BABELTRACE2
 * environment variable (default: "babeltrace2", i.e. found on PATH).
 */

const express = require('express');
const multer = require('multer');
const AdmZip = require('adm-zip');
const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const BT2 = process.env.BABELTRACE2 || 'babeltrace2';
const EXEC_TIMEOUT_MS = 30_000;

// Keep uploads in memory; individual trace files are small metadata/stream files.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024, files: 200 },
});

app.use(express.static(path.join(__dirname, 'public')));

// Health check endpoint for the hosting platform (Render).
app.get('/healthz', (_req, res) => res.json({ ok: true }));

// Run one babeltrace2 invocation and resolve with a structured result.
function runBt2(args, label, command) {
  return new Promise((resolve) => {
    execFile(
      BT2,
      args,
      { timeout: EXEC_TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err && err.code === 'ENOENT') {
          return resolve({
            label,
            command,
            available: false,
            error:
              `Could not find the "${BT2}" executable. Install Babeltrace 2 ` +
              `and/or set the BABELTRACE2 environment variable to its full path.`,
          });
        }
        resolve({
          label,
          command,
          available: true,
          exitCode: err && typeof err.code === 'number' ? err.code : 0,
          timedOut: Boolean(err && err.killed),
          success: !err,
          stdout: stdout || '',
          stderr: stderr || '',
        });
      }
    );
  });
}

// Locate the directory that actually contains the `metadata` file (uploads may
// nest it inside a folder, e.g. when a zip preserves a top-level directory).
function findTraceDir(root) {
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    if (entries.some((e) => e.isFile() && e.name === 'metadata')) return dir;
    for (const e of entries) {
      if (e.isDirectory()) stack.push(path.join(dir, e.name));
    }
  }
  return null;
}

app.post('/api/validate', upload.array('files'), async (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files were uploaded.' });
  }

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ctf-trace-'));
  try {
    // Materialize uploads. A single .zip is unpacked; everything else is
    // written using its (sanitized) original name.
    for (const file of req.files) {
      const name = file.originalname || 'unnamed';
      if (/\.zip$/i.test(name) && req.files.length === 1) {
        const zip = new AdmZip(file.buffer);
        zip.getEntries().forEach((entry) => {
          // Guard against zip-slip; keep entries inside workDir.
          const dest = path.join(workDir, entry.entryName);
          if (!dest.startsWith(workDir + path.sep)) return;
          if (entry.isDirectory) {
            fs.mkdirSync(dest, { recursive: true });
          } else {
            fs.mkdirSync(path.dirname(dest), { recursive: true });
            fs.writeFileSync(dest, entry.getData());
          }
        });
      } else {
        const safe = path.basename(name);
        fs.writeFileSync(path.join(workDir, safe), file.buffer);
      }
    }

    const traceDir = findTraceDir(workDir);
    if (!traceDir) {
      return res.json({
        traceDirFound: false,
        message:
          'No CTF "metadata" file was found in the upload. A CTF trace directory ' +
          'must contain a file literally named "metadata" (plus its stream files).',
        results: [],
      });
    }

    // 1. Metadata validation — parses the TSDL; errors on invalid metadata.
    const metaArgs = [
      'query', 'src.ctf.fs', 'metadata-info',
      '--params', `path="${traceDir}"`,
    ];
    // 2. Trace structure info — validates stream layout against the metadata.
    const infoArgs = [
      'query', 'src.ctf.fs', 'babeltrace.trace-infos',
      '--params', `inputs=["${traceDir}"]`,
    ];
    // 3. Full read — actually decode events end to end.
    const readArgs = ['-i', 'ctf', traceDir];

    // trace-infos and the full read need actual stream data files, not just
    // metadata. Detect whether any stream file was uploaded so we can skip
    // those checks with a clear message instead of a "Trace has no streams"
    // error when the user only wants to validate the metadata.
    const hasStreams = fs
      .readdirSync(traceDir, { withFileTypes: true })
      .some((e) => e.isFile() && e.name !== 'metadata');

    const skipped = (label, command) => ({
      label,
      command,
      available: true,
      skipped: true,
      message:
        'Skipped: this check decodes event streams, but the upload contains ' +
        'only a "metadata" file (no stream data files). Metadata validation ' +
        'above still fully checks the metadata. Upload the whole trace ' +
        'directory to run this check.',
    });

    const meta = await runBt2(
      metaArgs, 'Metadata validation', `${BT2} ${metaArgs.join(' ')}`
    );

    let info, read;
    if (hasStreams) {
      [info, read] = await Promise.all([
        runBt2(infoArgs, 'Trace structure (trace-infos)', `${BT2} ${infoArgs.join(' ')}`),
        runBt2(readArgs, 'Full trace read', `${BT2} ${readArgs.join(' ')}`),
      ]);
    } else {
      info = skipped('Trace structure (trace-infos)', `${BT2} ${infoArgs.join(' ')}`);
      read = skipped('Full trace read', `${BT2} ${readArgs.join(' ')}`);
    }

    res.json({
      traceDirFound: true,
      metadataOnly: !hasStreams,
      results: [meta, info, read],
    });
  } catch (e) {
    res.status(500).json({ error: String(e && e.message ? e.message : e) });
  } finally {
    fs.rm(workDir, { recursive: true, force: true }, () => {});
  }
});

app.listen(PORT, () => {
  console.log(`CTF trace validator running at http://localhost:${PORT}`);
  console.log(`Using babeltrace2 binary: ${BT2}`);
});
