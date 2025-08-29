const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');

const ARTIFACTS_DIR = './artifacts';
const OUTPUT_DIR = './dist';
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'data.js');

const artifactNames = [
  'bench-results-aarch64-unknown-linux-gnu',
  'bench-results-x86_64-unknown-linux-gnu'
];

const benchmarkData = {};

if (!fs.existsSync(ARTIFACTS_DIR)) {
  console.warn(`Artifacts directory not found: ${ARTIFACTS_DIR}`);
} else {
  for (const name of artifactNames) {
    const zipPath = path.join(ARTIFACTS_DIR, `${name}.zip`);
    if (!fs.existsSync(zipPath)) {
      console.warn(`Artifact zip not found: ${zipPath}`);
      continue;
    }

    try {
      const zip = new AdmZip(zipPath);
      const zipEntries = zip.getEntries();
      const jsonEntry = zipEntries.find(entry => entry.entryName.endsWith('.json'));

      if (jsonEntry) {
        const jsonContent = zip.readAsText(jsonEntry);
        benchmarkData[name] = JSON.parse(jsonContent);
        console.log(`Successfully processed ${name}`);
      } else {
        console.warn(`No JSON file found in artifact: ${name}`);
      }
    } catch (error) {
      console.error(`Error processing artifact ${name}:`, error);
    }
  }
}

const outputContent = `window.benchmarkData = ${JSON.stringify(benchmarkData, null, 2)};`;
fs.writeFileSync(OUTPUT_FILE, outputContent);

console.log(`Benchmark data written to ${OUTPUT_FILE}`);
