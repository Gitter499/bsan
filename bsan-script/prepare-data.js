const fs = require('fs');
const path = require('path');

const ARTIFACTS_DIR = '../artifacts';
const OUTPUT_DIR = '.';
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'data.js');

const benchmarkData = {};

function findJsonFiles(dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  list.forEach(function(file) {
    file = path.join(dir, file);
    const stat = fs.statSync(file);
    if (stat && stat.isDirectory()) {
      results = results.concat(findJsonFiles(file));
    } else if (file.endsWith('.json')) {
      results.push(file);
    }
  });
  return results;
}

if (!fs.existsSync(ARTIFACTS_DIR)) {
  console.warn(`Artifacts directory not found: ${ARTIFACTS_DIR}`);
} else {
  const artifactDirs = fs.readdirSync(ARTIFACTS_DIR);

  for (const dirName of artifactDirs) {
    const dirPath = path.join(ARTIFACTS_DIR, dirName);
    if (fs.statSync(dirPath).isDirectory()) {
      const jsonFiles = findJsonFiles(dirPath);

      if (jsonFiles.length > 0) {
        for (const jsonFile of jsonFiles) {
          try {
            const jsonContent = fs.readFileSync(jsonFile, 'utf-8');
            const benchmarkName = path.basename(jsonFile, '.json');
            if (!benchmarkData[dirName]) {
              benchmarkData[dirName] = {};
            }
            benchmarkData[dirName][benchmarkName] = JSON.parse(jsonContent);
            console.log(`Successfully processed ${jsonFile}`);
          } catch (error) {
            console.error(`Error processing artifact ${jsonFile}:`, error);
          }
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

if (Object.keys(benchmarkData).length === 0) {
  console.warn('No benchmark data was processed.');
}
