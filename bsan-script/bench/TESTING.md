# Manual Testing Plan for Benchmark Visualization

This document provides steps to manually test the benchmark visualization page.

## Setup

1.  **Install an HTTP Server:** If you don't have one, you can use Python's built-in server.
2.  **Navigate to the correct directory:** Open your terminal and change the directory to `bsan-script/bench/`.
    ```sh
    cd bsan-script/bench
    ```
3.  **Start the HTTP Server:**
    *   For Python 3: `python3 -m http.server`
    *   For Python 2: `python -m SimpleHTTPServer`
4.  **Open the page in your browser:** Open your web browser and navigate to `http://localhost:8000/` (or the address shown by your HTTP server). You should see the benchmark visualization page.

## Test Cases

### 1. Initial Page Load

*   **Verify:** The page should load without any errors.
*   **Verify:** The "Architecture" dropdown should be populated and have a default value selected.
*   **Verify:** The "Benchmark" dropdown should be populated with the benchmarks for the default architecture.
*   **Verify:** A chart should be displayed for the default benchmark.
*   **Verify:** The "Toggle Outlier" button should be visible and display the name of the outlier tool for the default benchmark (e.g., "Hide Miri (Outlier)").
*   **Action:** Open the browser's developer console (usually F12 or Ctrl+Shift+I).
*   **Verify:** There should be no errors in the console.

### 2. Dropdown Controls

*   **Action:** Change the "Architecture" dropdown.
*   **Verify:** The "Benchmark" dropdown should update with the benchmarks for the newly selected architecture.
*   **Verify:** The chart should update to show the data for the new architecture and the default benchmark.
*   **Verify:** The "Toggle Outlier" button should update to show the outlier for the new data.
*   **Action:** Change the "Benchmark" dropdown.
*   **Verify:** The chart should update to show the data for the newly selected benchmark.
*   **Verify:** The "Toggle Outlier" button should update.
*   **Action:** Change the "Chart Type" dropdown.
*   **Verify:** The chart should change to the selected type (Box Plot, Scatter Plot, Time Series).

### 3. Outlier Toggling

For a few different benchmarks:
1.  **Identify the outlier:** Note the tool with the highest execution time in the chart. The "Toggle Outlier" button should display this tool's name.
2.  **Action:** Click the "Toggle Outlier" button.
3.  **Verify:** The outlier tool should be removed from the chart. The button text should change to "Show <Outlier> (Outlier)". The Y-axis scale might change.
4.  **Action:** Click the "Toggle Outlier" button again.
5.  **Verify:** The outlier tool should reappear in the chart. The button text should change back to "Hide <Outlier> (Outlier)".

### 4. Cross-Browser Testing

*   **Recommendation:** If possible, repeat the above tests in at least two different web browsers (e.g., Google Chrome, Mozilla Firefox, Safari) to check for any browser-specific issues.
