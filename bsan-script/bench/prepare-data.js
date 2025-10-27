const fs = require('fs');
const path = require('path');

const ARTIFACTS_BASE_DIR = path.resolve(__dirname, '../../artifacts');
const LOCAL_RESULTS_DIR = path.resolve(__dirname, '../benches/results');
const OUTPUT_DIR = path.resolve(__dirname, './dist');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'data.js');

const benchmarkData = {};

const processRunDir = (runDirPath, architecture) => {
  if (!benchmarkData[architecture]) {
    benchmarkData[architecture] = {};
  }

  const benchmarkFiles = fs.readdirSync(runDirPath, { withFileTypes: true })
    .filter(dirent => dirent.isFile() && dirent.name.endsWith('.json'))
    .map(dirent => dirent.name);

  for (const benchmarkFileName of benchmarkFiles) {
    const benchmarkName = path.basename(benchmarkFileName, '.json');
    const benchmarkFilePath = path.join(runDirPath, benchmarkFileName);

    try {
      const fileContent = fs.readFileSync(benchmarkFilePath, 'utf8');
      if (fileContent.trim() === '') {
        console.warn(`Skipping empty file: ${runDirPath}/${benchmarkFileName}`);
        continue;
      }
      benchmarkData[architecture][benchmarkName] = JSON.parse(fileContent);
      console.log(`Successfully processed ${runDirPath}/${benchmarkFileName}`);
    } catch (error) {
      console.error(`Error processing ${runDirPath}/${benchmarkFileName}:`, error);
    }
  }
};

// Process CI artifacts if the directory exists
if (fs.existsSync(ARTIFACTS_BASE_DIR)) {
  const archDirs = fs.readdirSync(ARTIFACTS_BASE_DIR, { withFileTypes: true })
    .filter(dirent => dirent.isDirectory())
    .map(dirent => dirent.name);

  for (const archDirName of archDirs) {
    const archDirPath = path.join(ARTIFACTS_BASE_DIR, archDirName);
    const architecture = archDirName.replace('bench-results-', '');

    const runDirs = fs.readdirSync(archDirPath, { withFileTypes: true })
      .filter(dirent => dirent.isDirectory())
      .map(dirent => dirent.name);

    for (const runDirName of runDirs) {
      const runDirPath = path.join(archDirPath, runDirName);
      processRunDir(runDirPath, architecture);
    }
  }
}

// Process local results if the directory exists
if (fs.existsSync(LOCAL_RESULTS_DIR)) {
  benchmarkData['local-run'] = {};
  const runDirs = fs.readdirSync(LOCAL_RESULTS_DIR, { withFileTypes: true })
    .filter(dirent => dirent.isDirectory())
    .map(dirent => dirent.name);

  for (const runDirName of runDirs) {
    const runDirPath = path.join(LOCAL_RESULTS_DIR, runDirName);
    processRunDir(runDirPath, 'local-run');
  }
}

if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true }); // Ensure recursive creation
}

const outputContent = `window.benchmarkData = ${JSON.stringify(benchmarkData, null, 2)};`;
fs.writeFileSync(OUTPUT_FILE, outputContent);

console.log(`Benchmark data written to ${OUTPUT_FILE}`);
