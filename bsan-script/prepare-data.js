const fs = require('fs');
const path = require('path');

const ARTIFACTS_DIR = '../artifacts';
const OUTPUT_DIR = '.';
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'data.js');

const benchmarkData = {};

if (!fs.existsSync(ARTIFACTS_DIR)) {
  console.warn(`Artifacts directory not found: ${ARTIFACTS_DIR}`);
} else {
  const artifactDirs = fs.readdirSync(ARTIFACTS_DIR);

  for (const dirName of artifactDirs) {
    const dirPath = path.join(ARTIFACTS_DIR, dirName);
    if (fs.statSync(dirPath).isDirectory()) {
      const files = fs.readdirSync(dirPath);
      const jsonFile = files.find(file => file.endsWith('.json'));

      if (jsonFile) {
        const jsonFilePath = path.join(dirPath, jsonFile);
        try {
          const jsonContent = fs.readFileSync(jsonFilePath, 'utf-8');
          benchmarkData[dirName] = JSON.parse(jsonContent);
          console.log(`Successfully processed ${dirName}`);
        } catch (error) {
          console.error(`Error processing artifact ${dirName}:`, error);
        }
      } else {
        console.warn(`No JSON file found in artifact directory: ${dirName}`);
      }
    }
  }
}



const outputContent = `window.benchmarkData = ${JSON.stringify(benchmarkData, null, 2)};`;
fs.writeFileSync(OUTPUT_FILE, outputContent);

console.log(`Benchmark data written to ${OUTPUT_FILE}`);