const fs = require('fs');
const path = require('path');

const LATEST_DATA_PATH = path.resolve(__dirname, './dist/data.js');
// In the CI environment, the script runs from 'main/bsan-script/bench', and 'gh-pages' is at the root.
const HISTORY_PATH = path.resolve(__dirname, '../../../gh-pages/history.js');
const HISTORY_OUTPUT_PATH = path.resolve(__dirname, './dist/history.js');

const commitSha = process.argv[2];
if (!commitSha) {
  console.error('Error: Commit SHA is required as an argument.');
  process.exit(1);
}

let history = {};

// 1. Read existing history if it exists
if (fs.existsSync(HISTORY_PATH)) {
  try {
    const historyFileContent = fs.readFileSync(HISTORY_PATH, 'utf8');
    // The file is JS, not JSON. We need to extract the object.
    const jsonString = historyFileContent.replace('window.benchmarkHistory =', '').trim().slice(0, -1);
    if (jsonString) {
      history = JSON.parse(jsonString);
    }
  } catch (error) {
    console.warn(`Could not read or parse existing history file at ${HISTORY_PATH}. Starting fresh.`);
    console.warn(error.message);
    history = {};
  }
}

// 2. Read the new data from the latest run
let latestData = {};
if (fs.existsSync(LATEST_DATA_PATH)) {
  try {
    const latestDataContent = fs.readFileSync(LATEST_DATA_PATH, 'utf8');
    const jsonString = latestDataContent.replace('window.benchmarkData =', '').trim().slice(0, -1);
    if (jsonString) {
      latestData = JSON.parse(jsonString);
    }
  } catch (error) {
    console.error(`Error reading or parsing latest data file at ${LATEST_DATA_PATH}.`);
    console.error(error.message);
    process.exit(1);
  }
} else {
  console.error(`Latest data file not found at ${LATEST_DATA_PATH}.`);
  process.exit(1);
}

// 3. Append new data to history
history[commitSha] = latestData;

// 4. Write the updated history back
const outputContent = `window.benchmarkHistory = ${JSON.stringify(history, null, 2)};`;
try {
  fs.writeFileSync(HISTORY_OUTPUT_PATH, outputContent);
  console.log(`Successfully updated benchmark history at ${HISTORY_OUTPUT_PATH}`);
} catch (error) {
  console.error(`Error writing updated history file to ${HISTORY_OUTPUT_PATH}.`);
  console.error(error.message);
  process.exit(1);
}
