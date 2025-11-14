let toolSelection = {}; // Object to store the checked state of each tool
let outlierToolName = null;

const createChart = (architecture, benchmark_with_suffix, chartType) => {
  const chartsDiv = document.getElementById("charts-container");
  chartsDiv.innerHTML = ""; // Clear previous charts

  const archData = window.benchmarkData[architecture];
  if (!archData) {
    chartsDiv.innerHTML = `<p>No data found for architecture: ${architecture}</p>`;
    return;
  }

  const data = archData[benchmark_with_suffix];
  if (!data) {
    chartsDiv.innerHTML = `<p>No data found for benchmark: ${benchmark_with_suffix}</p>`;
    return;
  }

  // Find outlier for styling
  let maxMedian = 0;
  for (const result of data.results) {
      if (result.median > maxMedian) {
          maxMedian = result.median;
          outlierToolName = result.command;
      }
  }

  const selectedTools = Object.keys(toolSelection).filter(tool => toolSelection[tool]);

  const calculate_tool_transform = {
    "calculate": "datum.command",
    "as": "Tool"
  };

  const baseSpec = {
    "$schema": "https://vega.github.io/schema/vega-lite/v6.json",
    "width": 600,
    "height": 500,
    "data": {
      "values": data.results
    },
    "transform": [
      {"flatten": ["times"]},
      calculate_tool_transform,
      {"filter": {"field": "Tool", "oneOf": selectedTools}}
    ]
  };

  const commonYEncoding = {
    "field": "times",
    "type": "quantitative",
    "title": "Execution Time (s)",
    "axis": {"format": ".4f"},
    "scale": {"zero": false, "nice": true, "padding": 10}
  };

  const boxPlotSpec = {
    ...baseSpec,
    "title": "Benchmark Execution Time Comparison",
    "mark": {
      "type": "boxplot",
      "extent": "min-max",
      "size": 50,
      "box": { "stroke": "black", "strokeWidth": 2, "fillOpacity": 0.5 },
      "median": { "stroke": "black", "strokeWidth": 3 }
    },
    "encoding": {
      "x": {
        "field": "Tool",
        "type": "nominal",
        "title": "Tool",
        "sort": {"op": "median", "field": "times", "order": "ascending"},
        "axis": {"labelAngle": -45}
      },
      "y": commonYEncoding,
      "color": { "field": "Tool", "type": "nominal", "scale": {"scheme": "tableau10"} }
    }
  };

  const scatterPlotSpec = {
    ...baseSpec,
    "title": "Benchmark Execution Time Comparison",
    "layer": [
      {
        "mark": { "type": "point", "opacity": 0.6, "filled": true, "stroke": "black", "strokeWidth": 0.5 },
        "encoding": {
          "color": { "field": "Tool", "type": "nominal", "scale": {"scheme": "tableau10"}, "legend": { "title": "Tool", "orient": "bottom", "direction": "horizontal" }},
          "tooltip": [
            {"field": "Tool", "type": "nominal", "title": "Test"},
            {"field": "times", "type": "quantitative", "format": ".4f", "title": "Time (s)"}
          ]
        }
      },
      {
        "mark": { "type": "rule", "color": "skyblue", "opacity": 0.7, "size": 3 },
        "encoding": { "y": { "aggregate": "mean", "field": "times" } }
      }
    ],
    "encoding": {
      "x": { "field": "Tool", "type": "nominal", "title": "Tool", "sort": {"op": "median", "field": "times", "order": "ascending"}, "axis": {"labelAngle": -45} },
      "y": commonYEncoding
    }
  };

  const timeSeriesSpec = {
    ...baseSpec,
    "title": "Execution Time per Run with Average",
    "transform": [
      ...baseSpec.transform,
      { "window": [{"op": "row_number", "as": "run_number"}], "groupby": ["Tool"] }
    ],
    "layer": [
      {
        "mark": { "type": "point", "filled": true, "opacity": 0.3 },
        "encoding": {
          "x": { "field": "run_number", "type": "quantitative", "title": "Run Number", "axis": { "labelAngle": 0 } },
          "y": commonYEncoding,
          "color": { "field": "Tool", "type": "nominal", "title": "Tool" }
        }
      },
      {
        "mark": { "type": "rule", "size": 3, "opacity": 0.8 },
        "encoding": {
          "y": { "aggregate": "mean", "field": "times" },
          "color": { "field": "Tool", "type": "nominal" }
        }
      }
    ]
  };

  // If the outlier is selected, use a log scale. Otherwise, use a linear scale.
  const scaleType = toolSelection[outlierToolName] ? "log" : "linear";
  boxPlotSpec.encoding.y.scale.type = scaleType;
  timeSeriesSpec.layer[0].encoding.y.scale.type = scaleType;
  scatterPlotSpec.encoding.y.scale.type = scaleType;


  let spec;
  switch (chartType) {
    case "box": spec = boxPlotSpec; break;
    case "scatter": spec = scatterPlotSpec; break;
    case "time": spec = timeSeriesSpec; break;
  }

  const chartContainer = document.createElement("div");
  chartContainer.className = "chart-container";
  chartsDiv.appendChild(chartContainer);
  vegaEmbed(chartContainer, spec);
};

const main = () => {
  const themeToggle = document.getElementById("theme-toggle");
  const archSelect = document.getElementById("arch-select");
  const benchmarkSelect = document.getElementById("benchmark-select");
  const chartTypeSelect = document.getElementById("chart-type-select");
  const toolCheckboxesContainer = document.getElementById("tool-checkboxes");

  // Theme switching logic
  const applyTheme = (theme) => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("theme", theme);
  };

  themeToggle.addEventListener("click", () => {
    const currentTheme = document.documentElement.dataset.theme || "light";
    const newTheme = currentTheme === "light" ? "dark" : "light";
    applyTheme(newTheme);
  });

  // Apply saved theme on load
  const savedTheme = localStorage.getItem("theme");
  if (savedTheme) {
    applyTheme(savedTheme);
  }

  const populateArchitectures = () => {
    archSelect.innerHTML = "";
    const architectures = Object.keys(window.benchmarkData || {});
    for (const arch of architectures) {
      const option = document.createElement("option");
      option.value = arch;
      option.textContent = arch;
      archSelect.appendChild(option);
    }
  };

  const populateBenchmarks = (architecture) => {
    benchmarkSelect.innerHTML = "";
    const benchmarks = Object.keys(window.benchmarkData[architecture] || {});
    for (const benchmark of benchmarks) {
      const option = document.createElement("option");
      option.value = benchmark;
      option.textContent = benchmark.replace("-results", "");
      benchmarkSelect.appendChild(option);
    }
  };

  const populateTools = (architecture, benchmark_with_suffix) => {
    toolCheckboxesContainer.innerHTML = "";
    const archData = window.benchmarkData[architecture];
    if (!archData) return;
    const data = archData[benchmark_with_suffix];
    if (!data) return;

    const tools = data.results.map(r => r.command);
    
    // Find outlier for styling
    let maxMedian = 0;
    for (const result of data.results) {
        if (result.median > maxMedian) {
            maxMedian = result.median;
            outlierToolName = result.command;
        }
    }

    // Initialize tool selection state on first load for a benchmark
    const currentTools = Object.keys(toolSelection);
    const newTools = tools.filter(t => !currentTools.includes(t));
    if (newTools.length > 0 || currentTools.length === 0) {
        toolSelection = {};
        for (const tool of tools) {
            // By default, show all tools except the outlier.
            toolSelection[tool] = tool !== outlierToolName;
        }
    }
    
    for (const tool of tools) {
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.id = `tool-${tool}`;
      checkbox.value = tool;
      checkbox.checked = toolSelection[tool];

      const label = document.createElement("label");
      label.htmlFor = `tool-${tool}`;
      label.textContent = tool;

      if (tool === outlierToolName) {
        label.textContent += " (outlier)";
        label.classList.add("outlier-label");
        label.title = "This tool is the performance outlier.";
      }

      checkbox.addEventListener("change", () => {
        toolSelection[tool] = checkbox.checked;
        updateChart();
      });

      const container = document.createElement("div");
      container.classList.add("checkbox-container");
      container.appendChild(checkbox);
      container.appendChild(label);
      toolCheckboxesContainer.appendChild(container);
    }
  };

  const updateChart = () => {
    const selectedArch = archSelect.value;
    const selectedBenchmark = benchmarkSelect.value;
    const selectedChartType = chartTypeSelect.value;
    createChart(selectedArch, selectedBenchmark, selectedChartType);
  };

  const onSelectionChange = () => {
    const selectedArch = archSelect.value;
    const selectedBenchmark = benchmarkSelect.value;
    populateTools(selectedArch, selectedBenchmark);
    updateChart();
    createAgreementTable(selectedArch, selectedBenchmark); // Update agreement table
  };

  archSelect.addEventListener("change", onSelectionChange);
  benchmarkSelect.addEventListener("change", onSelectionChange);
  chartTypeSelect.addEventListener("change", updateChart);

  // Modal logic
  const modal = document.getElementById("output-modal");
  const closeButton = document.querySelector(".close-button");
  const modalStdout = document.getElementById("modal-stdout");
  const modalStderr = document.getElementById("modal-stderr");
  const copyStdoutButton = document.getElementById("copy-stdout");
  const copyStderrButton = document.getElementById("copy-stderr");

  const copyToClipboard = (text, button) => {
    navigator.clipboard.writeText(text).then(() => {
      const originalText = button.textContent;
      button.textContent = "Copied!";
      setTimeout(() => {
        button.textContent = originalText;
      }, 1500);
    }, (err) => {
      console.error('Could not copy text: ', err);
    });
  };

  copyStdoutButton.addEventListener("click", () => copyToClipboard(modalStdout.textContent, copyStdoutButton));
  copyStderrButton.addEventListener("click", () => copyToClipboard(modalStderr.textContent, copyStderrButton));

  closeButton.onclick = () => { modal.style.display = "none"; };
  window.onclick = (event) => {
    if (event.target == modal) {
      modal.style.display = "none";
    }
  };

  document.getElementById("agreement-table-container").addEventListener("click", (event) => {
    if (event.target.classList.contains("output-button")) {
      const stdout = event.target.dataset.stdout;
      const stderr = event.target.dataset.stderr;
      modalStdout.textContent = stdout || "(empty)";
      modalStderr.textContent = stderr || "(empty)";
      modal.style.display = "block";
    }
  });

  // Initial load
  if (window.benchmarkData && Object.keys(window.benchmarkData).length > 0) {
    populateArchitectures();
    const initialArch = archSelect.value;
    populateBenchmarks(initialArch);
    const initialBenchmark = benchmarkSelect.value;
    populateTools(initialArch, initialBenchmark);
    updateChart();
    createAgreementTable(initialArch, initialBenchmark);
    createHistoryTable(initialArch, initialBenchmark);
  } else {
    document.getElementById("charts-container").innerHTML = "<p>Benchmark data not loaded. Please ensure data.js is present and contains data.</p>";
  }

  // Tab switching logic
  const tabsContainer = document.querySelector(".tabs");
  tabsContainer.addEventListener("click", (event) => {
    if (event.target.classList.contains("tab-button")) {
      const tabButtons = document.querySelectorAll(".tab-button");
      const tabContents = document.querySelectorAll(".tab-content");
      const targetTab = event.target.dataset.tab;

      tabButtons.forEach(button => button.classList.remove("active"));
      event.target.classList.add("active");

      tabContents.forEach(content => {
        content.classList.remove("active");
        if (content.id === targetTab) {
          content.classList.add("active");
        }
      });
    }
  });
};

const createHistoryTable = (architecture, benchmark_with_suffix) => {
  const container = document.getElementById("history-table-container");
  container.innerHTML = "";

  if (!window.benchmarkHistory) {
    container.innerHTML = "<p>No history data available.</p>";
    return;
  }

  const commits = Object.keys(window.benchmarkHistory);
  if (commits.length < 2) {
    container.innerHTML = "<p>Not enough history data to compare.</p>";
    return;
  }

  const latestCommitSha = commits[commits.length - 1];
  const previousCommitSha = commits[commits.length - 2];

  const latestData = window.benchmarkHistory[latestCommitSha]?.[architecture]?.[benchmark_with_suffix];
  const previousData = window.benchmarkHistory[previousCommitSha]?.[architecture]?.[benchmark_with_suffix];

  if (!latestData || !previousData) {
    container.innerHTML = "<p>No comparable history for this specific benchmark.</p>";
    return;
  }

  let table = `<table id="history-table">
    <tr>
      <th>Tool</th>
      <th>Previous (${previousCommitSha.substring(0, 7)})</th>
      <th>Latest (${latestCommitSha.substring(0, 7)})</th>
      <th>Delta</th>
    </tr>`;

  const prevResultsMap = new Map(previousData.results.map(r => [r.command, r]));

  for (const latestResult of latestData.results) {
    const toolName = latestResult.command;
    const prevResult = prevResultsMap.get(toolName);

    if (prevResult) {
      const delta = ((latestResult.median - prevResult.median) / prevResult.median) * 100;
      const deltaSign = delta > 0 ? "+" : "";
      const deltaClass = delta > 0 ? "delta-positive" : "delta-negative";
      
      table += `
        <tr>
          <td>${toolName}</td>
          <td>${prevResult.median.toFixed(4)} s</td>
          <td>${latestResult.median.toFixed(4)} s</td>
          <td class="${deltaClass}">${deltaSign}${delta.toFixed(2)}%</td>
        </tr>`;
    }
  }

  table += `</table>`;
  container.innerHTML = table;
};

const createAgreementTable = (architecture, benchmark_with_suffix) => {
  const container = document.getElementById("agreement-table-container");
  container.innerHTML = "";

  const archData = window.benchmarkData[architecture];
  if (!archData) return;
  const data = archData[benchmark_with_suffix];
  if (!data || !data.results) return;

  let table = `<table id="agreement-table">
    <tr>
      <th>Tool</th>
      <th>Status</th>
      <th>Output</th>
    </tr>`;

  for (const result of data.results) {
    const toolName = result.command;
    const exitCodes = result.exit_codes || [];
    const hasFailed = exitCodes.some(code => code !== 0);
    const status = hasFailed ? "Fail" : "Pass";
    const statusClass = hasFailed ? "status-fail" : "status-pass";

    let outputButton = "";
    if (hasFailed && (result.stdout || result.stderr)) {
      outputButton = `<button class="output-button" data-stdout="${escapeHTML(result.stdout)}" data-stderr="${escapeHTML(result.stderr)}">Show</button>`;
    }

    table += `
      <tr>
        <td>${toolName}</td>
        <td class="${statusClass}">${status}</td>
        <td>${outputButton}</td>
      </tr>`;
  }

  table += `</table>`;
  container.innerHTML = table;
};

const escapeHTML = (str) => {
  if (!str) return "";
  return str.replace(/[&<>"']/g, (match) => {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[match];
  });
};

main();
