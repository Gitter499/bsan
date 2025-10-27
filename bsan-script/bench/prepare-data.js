const fs = require('fs');
const path = require('path');

const ARTIFACTS_BASE_DIR = path.resolve(__dirname, '../benches/results');
const OUTPUT_DIR = path.resolve(__dirname, './dist');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'data.js');

const benchmarkData = {};
benchmarkData['local-run'] = {}; // Aggregate all local runs under a single 'local-run' architecture

if (!fs.existsSync(ARTIFACTS_BASE_DIR)) {
  console.error(`Artifacts base directory not found: ${ARTIFACTS_BASE_DIR}`);
  process.exit(1);
}

// Read all subdirectories in ARTIFACTS_BASE_DIR (these are the timestamped run directories)
const runDirs = fs.readdirSync(ARTIFACTS_BASE_DIR, { withFileTypes: true })
  .filter(dirent => dirent.isDirectory())
  .map(dirent => dirent.name);

for (const runDirName of runDirs) {
  const runDirPath = path.join(ARTIFACTS_BASE_DIR, runDirName);

  // Read all JSON files in the current run directory
  const benchmarkFiles = fs.readdirSync(runDirPath, { withFileTypes: true })
    .filter(dirent => dirent.isFile() && dirent.name.endsWith('.json'))
    .map(dirent => dirent.name);

  for (const benchmarkFileName of benchmarkFiles) {
    const benchmarkName = path.basename(benchmarkFileName, '.json');
    const benchmarkFilePath = path.join(runDirPath, benchmarkFileName);

    try {
      const fileContent = fs.readFileSync(benchmarkFilePath, 'utf8');
      if (fileContent.trim() === '') {
        console.warn(`Skipping empty file: ${runDirName}/${benchmarkFileName}`);
        continue;
      }
      // For local runs, we'll just take the latest result for each benchmark
      // This assumes that the latest run directory is the one we care about
      // A more sophisticated approach would be to allow selecting different runs
      benchmarkData['local-run'][benchmarkName] = JSON.parse(fileContent);
      console.log(`Successfully processed ${runDirName}/${benchmarkFileName}`);
    } catch (error) {
      console.error(`Error processing ${runDirName}/${benchmarkFileName}:`, error);
    }
  }
}

if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true }); // Ensure recursive creation
}

const outputContent = `window.benchmarkData = ${JSON.stringify(benchmarkData, null, 2)};`;
fs.writeFileSync(OUTPUT_FILE, outputContent);

console.log(`Benchmark data written to ${OUTPUT_FILE}`);
