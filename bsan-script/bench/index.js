let showOutlier = true; // Show outlier by default
let outlierToolName = null;

const createChart = (architecture, benchmark_with_suffix, chartType) => {
  const chartsDiv = document.getElementById("charts");
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

  const benchmark = benchmark_with_suffix.replace("-results", "");

  // Find outlier
  let maxMedian = 0;
  let outlierCommand = null;
  for (const result of data.results) {
      if (result.median > maxMedian) {
          maxMedian = result.median;
          outlierCommand = result.command;
      }
  }
  outlierToolName = outlierCommand;

  const calculate_tool_transform = {
    "calculate": "datum.command",
    "as": "Tool"
  };

  const baseSpec = {
    "$schema": "https://vega.github.io/schema/vega-lite/v6.json",
    "width": 600,
    "height": 400,
    "data": {
      "values": data.results
    },
    "transform": [
      {"flatten": ["times"]},
      calculate_tool_transform,
      {"filter": showOutlier ? "datum.Tool !== null" : `datum.Tool !== '${outlierToolName}'`}
    ]
  };

  const boxPlotSpec = {
    ...baseSpec,
    "title": "Benchmark Execution Time Comparison",
    "mark": {
      "type": "boxplot",
      "extent": "min-max",
      "size": 50,
      "box": {
        "stroke": "black",
        "strokeWidth": 2,
        "fillOpacity": 0.5
      },
      "median": {
        "stroke": "black",
        "strokeWidth": 3
      }
    },
    "encoding": {
      "x": {
        "field": "Tool",
        "type": "nominal",
        "title": "Tool",
        "sort": {"op": "median", "field": "times", "order": "ascending"}
      },
      "y": {
        "field": "times",
        "type": "quantitative",
        "title": "Execution Time (s)",
        "scale": {"type": "linear"},
        "axis": {"format": ".4f", "tickCount": 50},
        "scale": {"nice": true, "padding": 10}
      },
      "color": {
        "field": "Tool",
        "type": "nominal",
        "scale": {"scheme": "tableau10"}
      }
    }
  };

  const scatterPlotSpec = {
    ...baseSpec,
    "title": "Benchmark Execution Time Comparison",
    "layer": [
      {
        "mark": {
          "type": "point",
          "opacity": 0.6,
          "filled": true,
          "stroke": "black",
          "strokeWidth": 0.5
        },
        "encoding": {
          "color": {
            "field": "Tool",
            "type": "nominal",
            "scale": {"scheme": "tableau10"},
            "legend": {
              "title": "Tool",
              "orient": "bottom",
              "direction": "horizontal"
            }
          },
          "tooltip": [
            {"field": "Tool", "type": "nominal", "title": "Test"},
            {"field": "times", "type": "quantitative", "format": ".4f", "title": "Time (s)"}
          ]
        }
      },
      {
        "mark": {
          "type": "rule",
          "color": "skyblue",
          "opacity": 0.7,
          "size": 3
        },
        "encoding": {
          "y": {
            "aggregate": "mean",
            "field": "times"
          }
        }
      }
    ],
    "encoding": {
      "x": {
        "field": "Tool",
        "type": "nominal",
        "title": "Tool",
        "sort": {"op": "median", "field": "times", "order": "ascending"}
      },
      "y": {
        "field": "times",
        "type": "quantitative",
        "title": "Execution Time (s)",
        "scale": {"type": "linear"},
        "axis": {"format": ".4f", "tickCount": 10}
      }
    }
  };

  const timeSeriesSpec = {
    ...baseSpec,
    "title": "Execution Time per Run with Average",
    "transform": [
      ...baseSpec.transform,
      {
        "window": [{"op": "row_number", "as": "run_number"}],
        "groupby": ["Tool"]
      }
    ],
    "layer": [
      {
        "mark": {
          "type": "point",
          "filled": true,
          "opacity": 0.3
        },
        "encoding": {
          "x": {
            "field": "run_number",
            "type": "quantitative",
            "title": "Run Number",
            "axis": {
              "labelAngle": 0
            }
          },
          "y": {
            "field": "times",
            "type": "quantitative",
            "title": "Execution Time (s)",
            "scale": {"zero": false},
            "axis": {"format": ".4f", "tickCount": 10}
          },
          "color": {
            "field": "Tool",
            "type": "nominal",
            "title": "Tool"
          }
        }
      },
      {
        "mark": {
          "type": "rule",
          "size": 3,
          "opacity": 0.8
        },
        "encoding": {
          "y": {
            "aggregate": "mean",
            "field": "times"
          },
          "color": {
            "field": "Tool",
            "type": "nominal"
          }
        }
      }
    ]
  };

  if (showOutlier) {
    boxPlotSpec.encoding.y.scale.type = "log"; // CHANGED: Apply log scale to boxPlotSpec
    timeSeriesSpec.layer[0].encoding.y.scale.type = "log";
    scatterPlotSpec.encoding.y.scale.type = "log";
  }

  let spec;
  switch (chartType) {
    case "box":
      spec = boxPlotSpec;
      break;
    case "scatter":
      spec = scatterPlotSpec;
      break;
    case "time":
      spec = timeSeriesSpec;
      break;
  }

  const chartContainer = document.createElement("div");
  chartContainer.className = "chart-container"; // ADDED: Add class for styling
  chartsDiv.appendChild(chartContainer);
  vegaEmbed(chartContainer, spec);
};

  const main = () => {
    console.log("window.benchmarkData:", window.benchmarkData);
    const archSelect = document.getElementById("arch-select");
    const benchmarkSelect = document.getElementById("benchmark-select");
    const chartTypeSelect = document.getElementById("chart-type-select");
    const outlierToggle = document.getElementById("outlier-toggle");

    const populateArchitectures = () => {
      archSelect.innerHTML = ""; // Clear existing options
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
        option.textContent = benchmark;
        benchmarkSelect.appendChild(option);
      }
    };

    const updateChart = () => {
      const selectedArch = archSelect.value;
      const selectedBenchmark = benchmarkSelect.value;
      const selectedChartType = chartTypeSelect.value;
      createChart(selectedArch, selectedBenchmark, selectedChartType);
      updateOutlierButton();
    };

    const updateOutlierButton = () => {
      if (outlierToolName) {
          outlierToggle.textContent = showOutlier ? `Hide ${outlierToolName} (Outlier)` : `Show ${outlierToolName} (Outlier)`;
      } else {
          outlierToggle.textContent = "Toggle Outlier";
      }
    };

    archSelect.addEventListener("change", () => {
      populateBenchmarks(archSelect.value);
      updateChart();
    });

    benchmarkSelect.addEventListener("change", updateChart);
    chartTypeSelect.addEventListener("change", updateChart);

    outlierToggle.addEventListener("click", () => {
      showOutlier = !showOutlier;
      updateChart();
    });

    // Initial load
    if (window.benchmarkData && Object.keys(window.benchmarkData).length > 0) {
      populateArchitectures();
      const initialArch = archSelect.value;
      populateBenchmarks(initialArch);
      updateChart();
    } else {
      document.getElementById("charts").innerHTML = "<p>Benchmark data not loaded. Please ensure data.js is present and contains data.</p>";
    }
  };

  main();