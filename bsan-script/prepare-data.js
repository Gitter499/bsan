const fs = require('fs');
const path = require('path');

const ARTIFACTS_BASE_DIR = path.resolve(__dirname, '../artifacts');
const OUTPUT_DIR = path.resolve(__dirname, './dist');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'data.js');

const benchmarkData = {};

if (!fs.existsSync(ARTIFACTS_BASE_DIR)) {
  console.error(`Artifacts base directory not found: ${ARTIFACTS_BASE_DIR}`);
  process.exit(1);
}

// Read all subdirectories in ARTIFACTS_BASE_DIR (these are the architecture-specific result directories)
const architectureDirs = fs.readdirSync(ARTIFACTS_BASE_DIR, { withFileTypes: true })
  .filter(dirent => dirent.isDirectory())
  .map(dirent => dirent.name);

for (const archDirName of architectureDirs) {
  const archDirPath = path.join(ARTIFACTS_BASE_DIR, archDirName);
  benchmarkData[archDirName] = {};

  const findJsonFiles = (dir, fileList = []) => {
    const files = fs.readdirSync(dir);
    files.forEach(file => {
      const filePath = path.join(dir, file);
      if (fs.statSync(filePath).isDirectory()) {
        findJsonFiles(filePath, fileList);
      } else if (path.extname(file) === '.json') {
        fileList.push(filePath);
      }
    });
    return fileList;
  };

  const jsonFiles = findJsonFiles(archDirPath);

  for (const benchmarkFilePath of jsonFiles) {
    const benchmarkName = path.basename(benchmarkFilePath, '.json');
    try {
      const fileContent = fs.readFileSync(benchmarkFilePath, 'utf8');
      if (fileContent.trim() === '') {
        console.warn(`Skipping empty file: ${benchmarkFilePath}`);
        continue;
      }
      benchmarkData[archDirName][benchmarkName] = JSON.parse(fileContent);
      console.log(`Successfully processed ${benchmarkFilePath}`);
    } catch (error) {
      console.error(`Error processing ${benchmarkFilePath}:`, error);
    }
  }
}

if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true }); // Ensure recursive creation
}

const outputContent = `window.benchmarkData = ${JSON.stringify(benchmarkData, null, 2)};`;
fs.writeFileSync(OUTPUT_FILE, outputContent);

console.log(`Benchmark data written to ${OUTPUT_FILE}`);
